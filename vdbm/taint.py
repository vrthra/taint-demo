import types
import inspect
import functools
import collections

class tstr(str):
    def __new__(cls, value):
        s = str.__new__(cls, value)
        s._s = value
        return s

    def __radd__(self, o): return tstr(str.__add__(o, self))

    def __repr__(self): return 'Tainted: ' + str.__repr__(self)

    def untaint(self): return self._s

def mark(module):
    for name in dir(module):
        obj = getattr(module, name)
        if isinstance(obj, types.FunctionType) or isinstance(obj, types.BuiltinFunctionType):
            yield (module, name, obj)

def sink(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        for e in (list(args) + list(kwargs.values())):
            if isinstance(e, tstr): raise Exception("tainted")
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

def make_strtuple_wrapper(fun):
    def proxy(*a, **kw): return tuple(tstr(l) for l in fun(*a, **kw))
    return 

def make_strlst_wrapper(fun):
    def proxy(*a, **kw): return [tstr(l) for l in fun(*a, **kw)]
    return proxy

def make_str_wrapper(fun):
    def proxy(*a, **kw): return tstr(fun(*a, **kw))
    return proxy

for name, fn in inspect.getmembers(str, callable):
    tuple_names = ['partition', 'rpartition']
    bool_names = ['__eq__', '__lt__', '__gt__', '__contains__']
    list_names = ['rsplit', 'splitlines', 'split']
    repr_names =  ['__repr__', '__str__', '__hash__']
    if name not in ['__class__', '__new__', '__init__', '__getattribute__',
            '__init_subclass__', '__subclasshook__', '__setattr__',
            '__len__', 'find', 'rfind', '__iter__'
            ] + tuple_names + list_names + bool_names + repr_names:
        setattr(tstr, name, make_str_wrapper(fn))
    elif name in list_names: setattr(tstr, name, make_strlst_wrapper(fn))
    elif name in tuple_names: setattr(tstr, name, make_strtuple_wrapper(fn))

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

