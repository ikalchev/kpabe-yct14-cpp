import os

CXXFLAGS = ["-std=gnu++14",]

def getNativeEnv():
   INCLUDES = [
      "-I.",
      "-I/usr/local/include",
      "-I/usr/local/include/pbc",
   ]
   LIBPATH = [
     "#",
     "/usr/local/lib",
   ]
   LIBS = [
     "pbc",
     "gmp",
     "mbedcrypto",
     "m",
   ]

   env = DefaultEnvironment(CXXFLAGS=CXXFLAGS + ["-Os"] + INCLUDES,
                            LIBS=LIBS,
                            LIBPATH=LIBPATH)
   return env

def kpabeLib(env):
   return env.StaticLibrary("kpabe", ["kpabe.cpp"])

def registerTests(env):
   BOOST_H = "/usr/local/include/boost"
   BOOST_TEST_LIB = "boost_unit_test_framework"

   files = ["kpabe_test.cpp"]
   testEnv = env.Clone()
   testEnv["LIBS"].extend(["kpabe", BOOST_TEST_LIB])
   testCases = [];
   for f in files:
      targetFile = os.path.join("#",
                                str(f).split('.')[0].split(os.path.sep)[-1])
      testCases.append(testEnv.Program(targetFile, [f]))

   return testCases

def registerMain(env):
  mainEnv = env.Clone()
  mainEnv["LIBS"].append("kpabe")
  return mainEnv.Program("main", "#main.cpp")

def collectNativeTargets(env):
   targets = registerTests(env) + registerMain(env)
   return targets

env = getNativeEnv()
env.Default(collectNativeTargets(env) + kpabeLib(env))
