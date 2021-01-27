from setuptools import setup, find_packages

kwargs = {}
kwargs["install_requires"] = [
    "stix2",
    "taxii2-client",
    "rdflib"]

kwargs["tests_require"] = [
    "pytest"
]

#packages = find_packages(exclude=("tests/*"))

setup(
    name="attackmodel", 
    description="A module for converting Mitre Att&ck® to an RDF model",
    author="Morton Swimmer",
    author_email="morton.swimmer@gmail.com",
    python_requires=">=3.8",
    classifiers=[
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "License :: OSI Approved :: MIT License",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Operating System :: OS Independent",
        "Natural Language :: English",
    ],
    long_description="""
    tbc
    """,
    packages=['attackmodel'],
    package_dir={'':'.'},
    **kwargs
)
