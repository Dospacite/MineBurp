# Intruder and Sequencer

Open either tool from a captured packet's history context menu. Ctrl+9 opens Intruder; Ctrl+0 opens Sequencer. Both views keep their state when switching views and save configuration, samples, and results in the current project. Work restores when reopening it; running sends and live collection never resume automatically. **Copy results as JSON** copies a report. See [workbench tools](WORKBENCH.md) for persistence, payload generators, selection actions, and limits. Injected traffic is recorded through the existing Repeater/proxy pipeline.

## Intruder

Intruder builds each attempt from the original captured logical frame. It does not mutate the previous attempt's output.

- **Sniper** changes one position at a time, using that position's payload list.
- **Battering ram** applies each value in the first payload list to every position.
- **Pitchfork** advances the lists together and stops at the shortest list.
- **Cluster bomb** enumerates every combination, with the last position changing fastest.

Select decoded fields for typed edits with length-prefix repair. Alternatively choose raw byte ranges and provide hexadecimal payloads. Raw offsets include the packet ID, but exclude transport framing, compression, and encryption. Ranges must not overlap. Replacements run from the highest offset downward so resizing one range does not move another. Mixing raw ranges and decoded fields in one attack is rejected.

Each line is one payload. Empty lines intentionally represent empty payloads. Use **Preview first attempt without sending** to inspect the generated logical hex. Start requires a live proxy connection whose protocol version and state match the seed. That condition is checked before every send. A run stops at its first error. Stop cancels pending work and pacing; a send already submitted to the proxy may finish.

Limits are 16 positions, 1,000 attempts, 1,000 values per list, 4,096 characters per value, and a complete seed packet no larger than 1 MiB. The observation window is 50–60,000 ms and also paces attempts. Runs are sequential.

Results report generated frame size, elapsed processing/observation time, and opposite-direction packet/byte counts observed after each send. These are time-window observations, not request-response correlations or vulnerability verdicts. Unrelated traffic can appear; delayed responses and packets not yet persisted can be missed. At most 251 observed packets are counted per attempt. Elapsed time includes backend calls and the observation wait, so it is not network round-trip time.

## Sequencer

Choose a decoded field and collect existing history in ascending packet order, or start live collection from the current end of the connection. Collection matches the seed's connection, direction, state, packet ID, channel, and protocol. Missing fields, empty values, and multiline values are skipped and counted. A collection scans at most 10,000 packets. Stop keeps samples already collected.

You can also paste samples, one per line. Empty lines are ignored. Analyze requires 2–10,000 samples, no more than 4,096 UTF-8 bytes each and 4 MiB combined.

The report includes unique and duplicate values, adjacent repeats, byte-length range, per-position Shannon entropy, distinct byte counts, most common byte frequency, and Pearson correlation of matching byte offsets in consecutive samples. Correlation is undefined when either side has zero variance. Variable-length positions use only samples containing that position.

These statistics describe observed UTF-8 representations. They do not decode hex/base64 into binary tokens, estimate cryptographic strength, or prove unpredictability. Counters and other predictable generators can score high entropy. This version does not implement Burp's full statistical test suite.
