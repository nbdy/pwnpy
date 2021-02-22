from setuptools.command.sdist import sdist
from setuptools import setup, find_packages
from os.path import isfile


class InstallSetupScript(sdist):
    def run(self):
        try:
            self.spawn(['sudo', 'apt-get', 'install', '-y', 'python3', 'python3-dev', 'python3-pip', 'gpsd',
                        'gpsd', 'gpsd-clients', 'libgps-dev', 'python-gps', 'libopenjp2-tools', 'aircrack-ng'])
            if isfile("/sys/firmware/devicetree/base/model"):
                self.spawn(['curl', 'https://raw.githubusercontent.com/nbdy/clean-shutdown/master/setup.sh', '|',
                            'bash'])
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
        'License :: OSI Approved :: MIT License'
    ],
    keywords="wardriving tool raspberry pi",
    packages=find_packages(),
    install_requires=[
        "gps", "scapy", "loguru", "btpy", "spidev", "Pillow", "podb", "pyrunnable", "pyclsload"
    ],
    cmdclass={
        'install': InstallSetupScript
    },
    entry_points={
        'console_scripts': [
            'pwnpy = pwnpy.__main__:main'
        ]
    },
    package_data={
        "pwnpy": ["modules/*"]
    },
    long_description_content_type="text/markdown",
)
