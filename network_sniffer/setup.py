from setuptools import find_packages, setup

package_name = 'network_sniffer'

setup(
    name=package_name,
    version='0.0.1',
    packages=find_packages(exclude=['test']),
    data_files=[
        ('share/ament_index/resource_index/packages',
            ['resource/' + package_name]),
        ('share/' + package_name, ['package.xml']),
    ],
    install_requires=['setuptools'],
    zip_safe=True,
    maintainer='Mehdi-Hassa',
    maintainer_email='user@example.com',
    description='A basic ROS2 network packet sniffer node using scapy.',
    license='MIT',
    tests_require=['pytest'],
    entry_points={
        'console_scripts': [
            'sniffer_node = network_sniffer.sniffer_node:main',
        ],
    },
)
