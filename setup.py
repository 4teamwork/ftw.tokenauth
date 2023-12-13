from setuptools import find_packages
from setuptools import setup
import os

version = '1.2.0'

tests_require = [
    'unittest2',
    'ftw.builder',
    'ftw.testbrowser',
    'ftw.testing',
    'plone.app.testing',
    'plone.rest',
    'plone.restapi',
    'requests',
    'plone.testing',
    'zope.configuration',
]


setup(name='ftw.tokenauth',
      version=version,
      description="Token Authentication for Plone",
      long_description=open("README.rst").read() + "\n\n" + open(
          os.path.join("docs", "HISTORY.txt")).read(),

      classifiers=[
          "Environment :: Web Environment",
          'Framework :: Plone',
          'Framework :: Plone :: 4.3',
          "Intended Audience :: Developers",
          'License :: OSI Approved :: GNU General Public License (GPL)',
          'Programming Language :: Python',
          'Topic :: Software Development :: Libraries :: Python Modules',
      ],

      keywords='token authentication plone oauth2 jwt',
      author='4teamwork AG',
      author_email='mailto:info@4teamwork.ch',
      url='https://github.com/4teamwork/ftw.tokenauth',
      license='GPL2',

      packages=find_packages(exclude=['ez_setup']),
      namespace_packages=['ftw'],
      include_package_data=True,
      zip_safe=False,


      install_requires=[
          'setuptools',
          # Plone / Zope dependencies
          'AccessControl',
          'Plone',
          'plone.api',
          'plone.supermodel',
          'Products.CMFCore',
          'Products.CMFPlone',
          'Products.PluggableAuthService',
          'z3c.form',
          'zExceptions',
          'ZODB3',
          'zope.component',
          'zope.globalrequest',
          'zope.interface',
          'zope.schema',
          'Zope2',
          # Other dependencies
          'cryptography < 3.4',
          'ftw.profilehook',
          'ftw.upgrade',
          'ipaddress',
          'PyJWT',
      ],
      tests_require=tests_require,
      extras_require=dict(tests=tests_require),

      entry_points="""
      # -*- Entry points: -*-
      [z3c.autoinclude.plugin]
      target = plone
      """)
