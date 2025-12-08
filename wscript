from waflib.Tools.compiler_cxx import cxx_compiler
#from scripts.waf import utils

import subprocess
import os
import sys

APPNAME = 'harpocrates' #TODO: REPLACE
VERSION = '1.0.0' #TODO: REPLACE

cxx_compiler['linux'] = ['clang++']

def options(opt) :
    opt.load('compiler_cxx')

def configure(cnf) :
    cnf.load('compiler_cxx')
    cnf.env.append_value('CXXFLAGS', ['-std=c++17', '-Wall', '-O3'])#, '-Werror', '-Wextra', '-O3'])

    if sys.platform == 'darwin':
            sdkpath = subprocess.check_output(['xcrun', '--show-sdk-path'], text=True).strip()
            print(f'Using SDK path: {sdkpath}')
            cnf.env.append_value('CXXFLAGS',
                                 [f'-isysroot{sdkpath}', '-stdlib=libc++', '-I/usr/local/opt/openssl/include'])

            cnf.env.append_value('LINKFLAGS', ['-L/usr/local/opt/openssl/lib'])

    cnf.env.append_value('LINKFLAGS', ['-pthread', '-lcrypto'])


def build(bld):
    # REPLACE PROJECT NAME
    bld(name = 'harpocrates_includes',
        includes='./include',
        export_includes='./include')


    print(bld.env.CXXFLAGS)
    bld.stlib(name = 'harpocrates',
        features = 'cxx cxxstlib',
        target='harpocrates',
        includes='../src',
        source=bld.path.ant_glob('src/harpocrates/**/*.cpp'),
        libs = ['crypto'],
        use = ['harpocrates_includes'])

    print(bld.env.CXXFLAGS)
    # bld(name='benchmark',
    #     features='cxx cxxprogram',
    #     target='benchmark',
    #     source='measurements/benchmark.cpp',
    #     libs = ['crypto'],
    #     use=['harpocrates_includes', 'harpocrates'],
    # )

    # # Build Examples
    # bld.recurse('examples/simple_example')
    # bld.recurse('examples/simple_encrypt_ctr_example')

    # Build Test
    bld.recurse('test/test_encrypt_decrypt')
#    bld.recurse('test/test_hashing')
#    bld.recurse('test/test_hashing_with_pointers')

def test(t):
    run_tests('build/test')

def doc(dc):
    generate_documentation()

# run_tests
# finds all test locate in the sub dirs of base dir and executes them
# @param base_dir your test folder
def run_tests(base_dir):

    platform = sys.platform
    if not base_dir.endswith('/'):
        base_dir = base_dir + '/'

    exec_cmd = './' + base_dir

    for dir in os.listdir(base_dir):
        current_dir = base_dir + dir

        for proc in os.listdir(current_dir):
            if not proc.endswith('.o'):
                cproc = './' + current_dir + '/' + proc
                os.system(cproc)

# Generate documentation for
# @param doc_tool the name of the document tool command
# @param config_file is the name of a potential config file
# @param params is a list of string of the parameters for the document tool
def generate_documentation(doc_tool='doxygen', params=None, config_file=None):

    param_str = ''
    if params:
        for param in params:
            param_str = param_str + param + ' '


    cmd = doc_tool + ' '

    if len(param_str) == 0:
        cmd = cmd + param_str

    if config_file:
        cmd = cmd + config_file

    os.system(cmd)
