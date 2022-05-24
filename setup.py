from setuptools import setup
from VERSION import version

with open("requirements.txt", "r") as f:
    requirementsStr = f.read()
requirementList = [requirement for requirement in requirementsStr.split("\n") if requirement != ""]

setup(name='schc-json-parser',
      version=version,
      description='SCHC Library to parse an unparse LoRaWAN SCHC Packets into and from a JSON Format',
      author='Ivan Martinez and Laurent Toutain',
      author_email='ivan-marino.martinez-bolivar@imt-atlantique.fr',
      url='https://github.com/openschc/schc-json-parser',
      packages=['SCHCParserTool'],
      long_description=open('README.md').read(),
      install_requires=requirementList,
      zip_safe=False)