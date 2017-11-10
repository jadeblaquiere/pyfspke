from setuptools import setup
from fspke import __version__

setup(name='fspke',
      description='Forward Secure Public Key Encryption based on Canetti, Halevi and Katz model',
      version=str(__version__),
      author='Joseph deBlaquiere',
      author_email='jadeblaquiere@yahoo.com',
      packages=['fspke'])