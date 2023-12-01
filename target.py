b = 2

dangerous = 99

# Assignment of a Source
a = retrieve_uname(request)
a = dangerous

# Aug Assignment
a += 2

# Unary Op
a = -1

# Binary Op
a = b + 2

# Bool Op
a = b and True

# Compare
a = b > a

# Binary Op + Call
a = 4 + add(b, a)

# Function evaluation should return a label

# Sink Call
query(a)

'''
a = retrieve_uname(request)
# a = dangerous
a += sanitize(a)

# Sink Assignment
sink = a
query(a)
'''