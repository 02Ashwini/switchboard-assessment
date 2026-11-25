
import express from 'express';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import { config } from './config.js';
import { getDb } from './db.js';
import { randomUUID } from 'node:crypto';

const app = express();
const server = createServer(app);

const WORKSPACES = ['ws_acme', 'ws_globex'];
const knownWorkspace = (ws: string) => WORKSPACES.includes(ws);

let ready = false;

app.get('/healthz', (_req, res) => {
  res.status(ready ? 200 : 503).json({ ok: ready });
});

// Verify Pigeon using the original, unmodified request bytes.
app.post(
  '/webhooks/pigeon',
  express.raw({ type: 'application/json', limit: '1mb' }),
  async (req, res) => {
    try {
      const raw = req.body as Buffer;
      const signature = req.header('x-pigeon-signature') || '';
      const match = /^t=(\d+),v1=([a-f0-9]{64})$/i.exec(signature);

      if (!Buffer.isBuffer(raw) || !match) {
        return res.sendStatus(401);
      }

      const timestamp = Number(match[1]);
      if (!Number.isFinite(timestamp) ||
          Math.abs(Date.now() / 1000 - timestamp) > 300) {
        return res.sendStatus(401);
      }

      const expected = createHmac('sha256', config.pigeon.webhookSecret)
        .update(`${match[1]}.${raw.toString('utf8')}`)
        .digest();

      const supplied = Buffer.from(match[2], 'hex');
      if (supplied.length !== expected.length ||
          !timingSafeEqual(expected, supplied)) {
        return res.sendStatus(401);
      }

      let event: any;
      try {
        event = JSON.parse(raw.toString('utf8'));
      } catch {
        return res.sendStatus(400);
      }

      if (!event || typeof event.id !== 'string') {
        return res.sendStatus(400);
      }

      if (!knownWorkspace(event.workspace)) {
        return res.sendStatus(200);
      }

      if (!['message.inbound', 'message.status'].includes(event.type)) {
        return res.sendStatus(200);
      }

      const db = await getDb();

      // Unique event ID makes webhook retries safe.
      try {
        await db.collection('pigeon_events').insertOne({
          _id: event.id,
          workspace: event.workspace,
          type: event.type,
          receivedAt: new Date(),
        });
      } catch (err: any) {
        if (err?.code === 11000) return res.sendStatus(200);
        throw err;
      }

      if (event.type === 'message.inbound') {
        const { message_id, from, text } = event.data || {};
        if (typeof message_id !== 'string' ||
            typeof from !== 'string') {
          return res.sendStatus(200);
        }

        await db.collection('inbound_messages').updateOne(
          { workspace: event.workspace, messageId: message_id },
          {
            $setOnInsert: {
              workspace: event.workspace,
              contact: from,
              messageId: message_id,
              text: String(text ?? ''),
              occurredAt: new Date(event.occurred_at || Date.now()),
            },
          },
          { upsert: true }
        );

        await db.collection('conversations').updateOne(
          { workspace: event.workspace, contact: from },
          {
            $setOnInsert: {
              workspace: event.workspace,
              contact: from,
              assignee: null,
              status: 'open',
              createdAt: new Date(),
            },
            $set: { updatedAt: new Date() },
          },
          { upsert: true }
        );
      }

      if (event.type === 'message.status') {
        const { client_ref, status } = event.data || {};
        if (typeof client_ref === 'string' &&
            ['sent', 'delivered', 'failed'].includes(status)) {
          await db.collection('outbound_messages').updateOne(
            { workspace: event.workspace, clientRef: client_ref },
            { $set: { status, updatedAt: new Date() } }
          );
        }
      }

      return res.sendStatus(200);
    } catch (err) {
      console.error('Webhook processing failed:', err);
      return res.sendStatus(503);
    }
  }
);

app.use(express.json());

// Grader endpoints
app.use('/__grader', (req, res, next) => {
  if (req.header('x-grader-token') !== config.graderToken) {
    return res.sendStatus(401);
  }
  next();
});


app.post('/__grader/reply', async (req, res) => {
  try {
    const { workspace, contact, text, client_ref } = req.body || {};

    if (
      !knownWorkspace(workspace) ||
      typeof contact !== 'string' ||
      typeof text !== 'string' ||
      !text.trim() ||
      typeof client_ref !== 'string' ||
      !client_ref
    ) {
      return res.sendStatus(400);
    }

    const db = await getDb();
    const messages = db.collection('outbound_messages');

    // Atomically reserve this client_ref. Concurrent retries share one record.
    try {
      await messages.insertOne({
        workspace,
        contact,
        text,
        clientRef: client_ref,
        status: 'queued',
        nextAttemptAt: new Date(),
        createdAt: new Date(),
      });
    } catch (err: any) {
      if (err?.code !== 11000) throw err;
    }

    await db.collection('conversations').updateOne(
      { workspace, contact },
      {
        $setOnInsert: {
          workspace,
          contact,
          assignee: null,
          status: 'open',
          createdAt: new Date(),
        },
        $set: { updatedAt: new Date() },
      },
      { upsert: true }
    );

    return res.sendStatus(202);
  } catch (err) {
    console.error('Reply enqueue failed:', err);
    return res.sendStatus(503);
  }
});


app.post('/__grader/reset', async (_req, res) => {
  try {
    const db = await getDb();
    await Promise.all([
      'pigeon_events',
      'inbound_messages',
      'outbound_messages',
      'conversations',
    ].map(name => db.collection(name).deleteMany({})));
    res.sendStatus(200);
  } catch (err) {
    console.error(err);
    res.sendStatus(500);
  }
});

app.get('/__grader/snapshot', async (_req, res) => {
  try {
    const db = await getDb();
    const workspaces: any = {};

    for (const ws of WORKSPACES) {
      workspaces[ws] = { contacts: {}, outbound: {} };

      const conversations = await db.collection('conversations')
        .find({ workspace: ws }).toArray();

      const inbound = await db.collection('inbound_messages')
        .find({ workspace: ws })
        .sort({ occurredAt: 1, _id: 1 }).toArray();

      for (const c of conversations) {
        workspaces[ws].contacts[c.contact] = {
          inbound: [],
          assignee: c.assignee ?? null,
        };
      }

      for (const m of inbound) {
        if (!workspaces[ws].contacts[m.contact]) {
          workspaces[ws].contacts[m.contact] = {
            inbound: [],
            assignee: null,
          };
        }
        workspaces[ws].contacts[m.contact].inbound.push(m.messageId);
      }

      const outbound = await db.collection('outbound_messages')
        .find({ workspace: ws }).toArray();

      for (const m of outbound) {
        workspaces[ws].outbound[m.clientRef] = m.status;
      }
    }

    res.json({ workspaces });
  } catch (err) {
    console.error(err);
    res.sendStatus(500);
  }
});

app.post('/__grader/claim', async (req, res) => {
  try {
    const { workspace, contact, agent } = req.body || {};
    if (!knownWorkspace(workspace) ||
        typeof contact !== 'string' ||
        typeof agent !== 'string') {
      return res.sendStatus(400);
    }

    const db = await getDb();
    const result = await db.collection('conversations').updateOne(
      {
        workspace,
        contact,
        $or: [{ assignee: null }, { assignee: agent }],
      },
      {
        $set: { assignee: agent, updatedAt: new Date() },
        $setOnInsert: {
          workspace,
          contact,
          status: 'open',
          createdAt: new Date(),
        },
      },
      { upsert: true }
    );

    if (result.matchedCount || result.upsertedCount) {
      return res.sendStatus(200);
    }

    return res.sendStatus(409);
  } catch (err: any) {
    if (err?.code === 11000) return res.sendStatus(409);
    console.error(err);
    return res.sendStatus(500);
  }
});


async function deliverReplies() {
  const db = await getDb();
  const collection = db.collection('outbound_messages');

  // Process one eligible reply at a time. The conditional update
  // prevents two server instances from taking the same queued item.
  const candidate = await collection.findOne({
    status: 'queued',
    nextAttemptAt: { $lte: new Date() },
  });

  if (!candidate) return;

  const lockToken = randomUUID();
  const claimed = await collection.updateOne(
    {
      _id: candidate._id,
      status: 'queued',
      nextAttemptAt: candidate.nextAttemptAt,
    },
    {
      $set: {
        lockToken,
        lockedAt: new Date(),
      },
    }
  );

  if (!claimed.modifiedCount) return;

  const message = await collection.findOne({
    _id: candidate._id,
    lockToken,
  });

  if (!message) return;

  const apiKey = config.pigeon.apiKeys[message.workspace];

  try {
    const response = await fetch(`${config.pigeon.url}/v1/messages`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
        'Idempotency-Key': message.clientRef,
      },
      body: JSON.stringify({
        to: message.contact,
        text: message.text,
        client_ref: message.clientRef,
      }),
    });

    if (response.ok) {
      await collection.updateOne(
        { _id: message._id, lockToken },
        {
          $set: {
            deliveryRequested: true,
            deliveryRequestedAt: new Date(),
          },
          $unset: { lockToken: '', lockedAt: '', nextAttemptAt: '' },
        }
      );
      return;
    }

    const retryAfter = Number(response.headers.get('retry-after'));
    const delay = response.status === 429 && Number.isFinite(retryAfter) && retryAfter > 0
      ? retryAfter * 1000
      : 3000;

    await collection.updateOne(
      { _id: message._id, lockToken },
      {
        $set: {
          nextAttemptAt: new Date(Date.now() + delay),
          lastError: `Pigeon HTTP ${response.status}`,
        },
        $unset: { lockToken: '', lockedAt: '' },
      }
    );
  } catch (error) {
    await collection.updateOne(
      { _id: message._id, lockToken },
      {
        $set: {
          nextAttemptAt: new Date(Date.now() + 3000),
          lastError: String(error),
        },
        $unset: { lockToken: '', lockedAt: '' },
      }
    );
  }
}

setInterval(() => {
  deliverReplies().catch(error =>
    console.error('Reply worker error:', error)
  );
}, 200);


server.listen(config.port, async () => {
  try {
    const db = await getDb();

    await Promise.all([
      
      db.collection('inbound_messages').createIndex(
        { workspace: 1, messageId: 1 }, { unique: true }
      ),
      db.collection('conversations').createIndex(
        { workspace: 1, contact: 1 }, { unique: true }
      ),
      db.collection('outbound_messages').createIndex(
        { workspace: 1, clientRef: 1 }, { unique: true }
      ),
    ]);

    ready = true;
    console.log(`server ready on port ${config.port}`);
  } catch (err) {
    console.error('Startup failed:', err);
    process.exit(1);
  }
});
