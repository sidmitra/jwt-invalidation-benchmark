# JWT Invalidation Benchmark (redis)

Scripts to benchmark JWT invalidation lists(blacklists) methods via redis

We can maintain simple list of invalidated tokens via

- Redis cache feature SET with expiry(px)
- Bloom filter on redis via the Walrus library

## Quickstart

- Install redis on your machine, ensure it's running on localhost:6379

- Run the following

```bash
pip install -r requirements.txt
python main.py
```

You can change the `NUM_TOKENS` in the script to insert more or less tokens.
The default runs with a million `1_000_000` randomly generated tokens.

### Output

```text
-----------
CacheTokenInvalidator:
Insert 1000000 took 38.60413399999379 seconds.
Querying 1000000 took 34.529506833001506 seconds, with 0 false positive
Mem used 140.20M
-----------
BloomFilterTokenInvalidator:
Insert 1000000 took 45.445146415993804 seconds.
Querying 1000000 took 42.697518625005614 seconds, with 0 false positive
Mem used 2.29M
```
