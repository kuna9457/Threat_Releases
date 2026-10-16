cache = {}

def get_cache(url: str):
    return cache.get(url)

def set_cache(url: str, data: dict):
    cache[url] = data
