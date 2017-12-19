import types
import inspect
import functools
import collections

class tstr(str):
    def __new__(cls, value, taint=True):
        s = str.__new__(cls, value)
        s._taint = taint
        return s

    def __radd__(self, other):
        return tstr(str.__add__(other, self), self._taint)

    def __repr__(self):
        return self.__class__.__name__ + str.__repr__(self) + " " + str(self.tainted())

    def tainted(self):
        return self._taint

    def untaint(self):
        self._taint = False
        return self

def mark(module):
    for name in dir(module):
        obj = getattr(module, name)
        if isinstance(obj, types.FunctionType) or isinstance(obj, types.BuiltinFunctionType):
            yield (module, name, obj)

def sink(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        for e in (list(args) + list(kwargs.values())):
           if isinstance(e, tstr) and e._taint:
              raise Exception("tainted: %s" % e._taint)
        return func(*args, **kwargs)
    return wrapper

def sanitizer(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        my_args = [a.untaint() for a in args]
        my_kwargs = {k:v.untaint() for k,v in kwargs}
        return func(*my_args, **my_kwargs)
    return wrapper

def mark_sinks(module):
    for (module, name, obj) in mark(module):
        setattr(module, name, sink(obj))

def make_str_wrapper(fun):
    def proxy(*args, **kwargs):
        res = fun(*args, **kwargs)
        if res.__class__ == str:
            return tstr(res, args[0]._taint)
        return res
    return proxy

for name, fn in inspect.getmembers(str, callable):
    if name not in ['__class__', '__new__', '__init__']:
        setattr(tstr, name, make_str_wrapper(fn))

def source(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        v = func(*args, **kwargs)
        if isinstance(v, list):
            return [tstr(l) for l in v]
        elif isinstance(v, tuple):
            return tuple(tstr(l) for l in v)
        elif isinstance(v, set):
            return set(tstr(l) for l in v)
        elif isinstance(v, dict):
            return {tstr(k):tstr(l) for k,l in v}
        elif isinstance(v, str):
            return tstr(v)
        elif isinstance(v, collections.Iterator):
            return ProxyIter(v)
        else:
            return v
    return wrapper

def mark_sources(module):
    for (module, name, obj) in mark(module):
        setattr(module, name, source(obj))

class ProxyIter(collections.Iterator):
    def __init__(self, i):
        self.i = i

    def __iter__(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return self.i.__exit__(exc_type, exc_val, exc_tb)

    def __next__(self):
        return tstr(self.i.__next__())

    def __hasattr__(self, name):
        return hasattr(self.i, name)

    def __getattr__(self, name):
        func = getattr(self.i,name)
        if not func: return None
        return source(func)

