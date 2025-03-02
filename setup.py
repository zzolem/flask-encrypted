from setuptools import setup, find_packages

with open( "README.md", "r") as f:
    long_description = f.read()

setup(
    name="Flask-Encrypted",
    version="0.0.1",
    author="zzolem",
    description= "Encrypted cookies for Flask",
    long_description_content_type="text/markdown",
    long_description = long_description,
    packages=find_packages(),
    install_requires=['cryptography', 'flask', 'msgpack'],
    keywords=['flask', 'cookie', 'cookies', 'session', 'encrypted', 'python'],
    # extras_require={
    #   "dev": ["pytest"],
    #},
    #python_requires=">3.10",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Operating System :: Unix",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
    ]
)
