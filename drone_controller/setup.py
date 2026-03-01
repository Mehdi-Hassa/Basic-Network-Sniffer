from setuptools import find_packages, setup

package_name = 'drone_controller'

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
    description='ROS2 nodes for drone control and telemetry monitoring.',
    license='MIT',
    tests_require=['pytest'],
    entry_points={
        'console_scripts': [
            'controller_node = drone_controller.controller_node:main',
            'telemetry_node  = drone_controller.telemetry_node:main',
        ],
    },
)
