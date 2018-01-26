"""SConstruct file that builds:
    - kpabe static lib
    - main.cpp
    - unittests
"""
import os

CXXFLAGS = ["-std=gnu++14",]

def getNativeEnv():
    """Get the environment.
    """
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

def getKpabeLib(env):
    """Get target for kpabe static lib.
    """
    return env.StaticLibrary("kpabe", ["kpabe.cpp"])

def getTestsTarget(env):
    """Get test targets.
    """
    BOOST_H = "/usr/local/include/boost"
    BOOST_TEST_LIB = "boost_unit_test_framework"

    files = ["kpabe_test.cpp"]
    testEnv = env.Clone()
    testEnv["LIBS"].insert(0, ["kpabe", BOOST_TEST_LIB])
    testCases = [];
    for f in files:
        targetFile = os.path.join("#",
                                  str(f).split('.')[0].split(os.path.sep)[-1])
        testCases.append(testEnv.Program(targetFile, [f]))

    return testCases

def getMainTarget(env):
    """Get main target.
    """
    mainEnv = env.Clone()
    mainEnv["LIBS"].insert(0, "kpabe")
    return mainEnv.Program("main", "#main.cpp")

def getAllTargets(env):
    """Get all targets.
    """
    targets = getTestsTarget(env) + getMainTarget(env)
    return targets

env = getNativeEnv()
env.Default(getAllTargets(env) + getKpabeLib(env))
