
import express from 'express';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import { config } from './config.js';
import { getDb } from './db.js';

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
