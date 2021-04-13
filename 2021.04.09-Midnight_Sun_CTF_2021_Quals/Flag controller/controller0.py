poly = [2902729971, 2489123933, 2644068349, 2269733222, 2384687599, 2356440788, 2398964685, 2147483735, 2269234982, 2187366107, 2397386383, 3833285719, 3535859463, 2164043895, 2478021403, 3006836182, 2178410311]
target = [734011278, 209537740, 3958617246, 3349389466, 2464394056, 1129970118, 3375675026, 2669433308, 1934295950, 1097250648, 2269507662, 4121041632, 2679946174, 616563080, 1268754702, 2443512142, 4118132610]

def update(state, bit):
 ret = []
 for var2, var3 in zip(poly, state):
  if var3 & 0x80000000:
   var3 ^= var2
  ret.append((var3 << 1) | bit)
 return ret

def compute(b):
 var1 = [0] * len(poly)
 for var2 in b:
  for i in range(8):
   var1 = update(var1, (var2 >> i) & 1)
 return var1

def check(b):
  return len(target) / (sum(1 if x == y else 0 for x, y in iter(zip(target, compute(b)))) * 100)
