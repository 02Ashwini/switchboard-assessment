# Assessment Decision Note

## Checker Results

| Assessment level | Result |
|---|---:|
| Level 1 – Inbound and outbound reliability | 21.83/24* |
| Level 5 – Authentication and real-time WebSockets | 14.7/15 |
| Level 2 – Process restart and recovery | 13.8/14 |

*Level 1 score recorded from the earlier checker output; verify against the complete checker report before submission.

## Engineering Decisions

- Used MongoDB unique indexes to prevent duplicate inbound and outbound records.
- Used Redis for session storage and cross-instance WebSocket messaging.
- Implemented authenticated WebSocket connections with workspace membership checks.
- Added message replay using Redis sequence numbers and stored history.
- Used a queued outbound worker with provider idempotency keys and retry handling.

## Known Limitations

- Level 1 status lifecycle had a partial result.
- Level 5 scored 14.7/15; the remaining discrepancy needs review.
- Level 2 restart and recovery testing is still pending.

## Testing and Verification

Record the final checker scores, any known failures, and the exact commands used. Do not claim a test passed unless its report confirms it.