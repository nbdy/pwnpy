from setuptools.command.sdist import sdist
from setuptools import setup, find_packages
from os.path import isfile


class InstallSetupScript(sdist):
    def run(self):
        try:
            self.spawn(['sudo', 'apt-get', 'install', '-y', 'python3', 'python3-dev', 'python3-pip',
                        'gpsd', 'gpsd-clients', 'libgps-dev', 'python-gps', 'libopenjp2-tools'])
            if isfile("/sys/firmware/devicetree/base/model"):
                self.spawn(['curl', 'https://raw.githubusercontent.com/nbdy/clean-shutdown/master/setup.sh', '|', 'bash'])
                self.spawn(['pip3', 'install', 'spidev', 'RPi.GPIO', 'numpy', 'PIL'])
        except Exception as e:
            print(e)
        super().run()


setup(
    long_description=open("README.md", "r").read(),
    name="pwnpy",
    version="1.00",
    description="wardriving tool",
    author="Pascal Eberlein",
    author_email="pascal@eberlein.io",
    url="https://github.com/nbdy/pwnpy",
    classifiers=[
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.9',
    ],
    keywords="wardriving tool raspberry pi",
    packages=find_packages(),
    install_requires=open("requirements.txt").readlines(),
    cmdclass={
        'sdist': InstallSetupScript
    },
    entry_points={
        'console_scripts': [
            'pwnpy = pwnpy.__main__:main'
        ]
    },
    package_data={
        "pwnpy": ["templates/*.html"]
    },
    long_description_content_type="text/markdown",
)
