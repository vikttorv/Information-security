#some useful functions
from datetime import datetime

timestamp = 1527917995.234857
dt = datetime.fromtimestamp(timestamp)
print (dt)
ts = datetime.timestamp (dt)
print (ts)

