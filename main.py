from abc import ABC, abstractmethod
import logging
import redis
import time
import uuid
from datetime import datetime, timedelta
from timeit import default_timer as timer
import walrus


NUM_TOKENS = 1_000_000


def jwt_token_generator(num=None):
    count = 0
    while True:
        if count <= num - 1:
            count = count + 1
            yield {
                "aud": "foo-bar",
                "jti": str(uuid.uuid4()),
                "exp": int(time.time()) + 60 * 60 * 24 * 14,  # expires in 2 weeks
            }
        else:
            count = count + 1
            break


def convert_bytes(size):
    for x in ["bytes", "KB", "MB", "GB", "TB"]:
        if size < 1024.0:
            return "%3.1f %s" % (size, x)
        size /= 1024.0

    return size


class RedisTokenInvalidator(ABC):
    """
    Interface for the validators
    """

    store = None

    def __init__(self, host="localhost", port=6379, db=0):
        raise NotImplementedError

    def clear(self):
        self.store.flushall()

    def mem_stats(self):
        info = self.store.info()
        return info["used_memory_human"]

    @staticmethod
    def get_invalidation_cache_key(decoded_token: dict) -> str:
        aud = decoded_token.get("aud")
        jti = decoded_token.get("jti")
        if not (jti or aud):
            raise ValueError("Token without aud or jti claims")
        return f"jwt-blacklist:{aud}:{jti}"

    @abstractmethod
    def invalidate_token(self, decoded_token: dict) -> bool:
        raise NotImplementedError

    @abstractmethod
    def is_token_valid(self, decoded_token: dict) -> bool:
        raise NotImplementedError


class CacheTokenInvalidator(RedisTokenInvalidator):
    """
    Maintains a list of keys invalidated by using their aud+jti claims.

    Each key is stored as a key/value pair where value is a dummy value 1.
    """

    def __init__(self, host="localhost", port=6379, db=0):
        self.store = redis.Redis(host=host, port=port, db=db)

    def invalidate_token(self, decoded_token: dict) -> bool:
        key = self.get_invalidation_cache_key(decoded_token)

        exp = decoded_token.get("exp")
        if not (key or exp):
            return ValueError("Token without key or exp")

        # 1 is a dummy value
        ttl = exp - int(time.time())  # seconds
        if ttl > 0:
            self.store.set(key, 1, ex=ttl)
        return True

    def is_token_valid(self, decoded_token: dict) -> bool:
        key = self.get_invalidation_cache_key(decoded_token)
        if key and self.store.get(key):
            return False

        return True


class BloomFilterTokenInvalidator(RedisTokenInvalidator):
    """
    Uses a walrus.BloomFilter on redis to maintain the list.

    The bloom filter is stored on a single key with a set size.
    There is no concept of expiry. The expiry has to be probably
    """

    def __init__(self, host="localhost", port=6379, db=0):
        self.store = walrus.Database(host=host, port=port, db=db)
        self.bloom_filter = self.store.bloom_filter("walrus:jwt-blacklist:")

    def invalidate_token(self, decoded_token: dict) -> bool:
        key = self.get_invalidation_cache_key(decoded_token)
        # not concept of expiry by default in a bloom filter
        if not key:
            return ValueError("Token without key")

        self.bloom_filter.add(key)
        return True

    def is_token_valid(self, decoded_token: dict) -> bool:
        key = self.get_invalidation_cache_key(decoded_token)
        if key and self.bloom_filter.contains(key):
            return False
        return True


def benchmark(invalidator, tokens, num_tokens):
    # Time to insert
    start_time = timer()
    for token in tokens:
        invalidator.invalidate_token(token)
    end_time = timer()
    time_taken = end_time - start_time
    print(f"Insert {num_tokens} took {time_taken} seconds.")

    # Time to query tokens back
    start_time = timer()
    num_errors = 0
    for token in tokens:
        is_valid = invalidator.is_token_valid(token)
        if is_valid:
            # Token should not be valid, since we just invalidated all of these above.
            num_errors = num_errors + 1

    end_time = timer()
    time_taken = end_time - start_time
    print(
        f"Querying {num_tokens} took {time_taken} seconds, "
        f"with {num_errors} false positive"
    )
    # Mem usage of store
    mem_used = invalidator.mem_stats()
    print(f"Mem used {mem_used}")


def main():
    tokens = []
    for token in jwt_token_generator(NUM_TOKENS):
        tokens.append(token)

    classes = [
        CacheTokenInvalidator,
        BloomFilterTokenInvalidator,
    ]
    for kls in classes:
        print("-----------")
        print(f"{kls.__name__}:")
        cache_invalidator = kls(host="localhost", port=6379, db=0)
        # clear everything before starting
        cache_invalidator.clear()
        benchmark(cache_invalidator, tokens, NUM_TOKENS)


if __name__ == "__main__":
    main()
