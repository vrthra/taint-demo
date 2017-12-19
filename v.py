import vdbm
with vdbm.open('cache') as db:
   print(db.get('hello'))
