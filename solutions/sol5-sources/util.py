from torch.utils.cpp_extension import load

def load_helper():
  return load(
    name = 'helper',
    sources = ['helper.cpp', 'DES.cpp'],
    with_cuda=False,
    extra_cflags=['-O3']
  )