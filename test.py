from libpurecool.dyson import DysonAccount
from libpurecool.const import FanSpeed
import logging

import time
import sys

dlg = logging.getLogger('libpurecool.dyson')
dlg.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(levelname)s;%(asctime)s;%(name)s;%(threadName)s;%(message)s')
# Add the log message handler to the logger
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(formatter)
dlg.addHandler(handler)

USER = "your@mail"
PASS = "password"
LANG = "FR"

def print_new_attributes():
    print(device)
    print(device.state, type(device.state))
    print(device.environmental_state, type(device.environmental_state))
    print("---")

def wait():
    print("Waiting for 10 seconds")
    time.sleep(10)
    print("Wait done!")

dyson_account = DysonAccount(USER, PASS, LANG)
while dyson_account.login() == False:
    if dyson_account.wait_2fa_start and \
       dyson_account.authent():
        print('authent ok!')
    if dyson_account.wait_2fa_verify and \
       dyson_account.verify(input("Please input token received by mail:")):
        print('verify ok!')
        break
    if dyson_account.wait_2fa_start == False:
        dyson_account.prune()
    time.sleep(1)
dyson_account.nukeDeviceCache()
devices = dyson_account.devices()
print(devices)

# ip of a pure cool humidify device
connected = devices[0].connect('192.168.88.27')
device = devices[0]

#print("Running tests... Turning on...")
#device.turn_on()
#wait()
print_new_attributes()
exit(0)

device.disconnect()
for i in FanSpeed:
    print(i, i.value)


if device.state.humidity_target == '0070':
    print("Setting humidity target to 60")
    device.set_humidity_target(60)
else:
    print("Setting humidity target to 70")
    device.set_humidity_target(70)
wait()
print_new_attributes()

print("Enabling humidifier")
device.enable_humidifier()
wait()
print_new_attributes()

print("Disabling humidifier")
device.disable_humidifier()
wait()
print_new_attributes()

if device.state.humidity_target == '0070':
    print("Setting humidity target to 60")
    device.set_humidity_target(60)
else:
    print("Setting humidity target to 70")
    device.set_humidity_target(70)
wait()
print_new_attributes()

print("Enabling humidifier auto mode")
device.enable_humidifier_auto()
wait()
print_new_attributes()

print("Disabling humidifier auto mode")
device.disable_humidifier_auto()
wait()
print_new_attributes()


print("Enabling fan auto mode")
device.enable_auto_mode()
wait()
print_new_attributes()

print("Disabling fan auto mode")
device.disable_auto_mode()
wait()
print_new_attributes()

print("Enabling night mode")
device.enable_auto_mode()
wait()
print_new_attributes()

print("Disabling night mode")
device.enable_auto_mode()
wait()
print_new_attributes()

print("on mode")
device.turn_on()
wait()
print_new_attributes()

print("set fan to FAN_SPEED_5")
device.set_fan_speed(FanSpeed.FAN_SPEED_5)
wait()
print_new_attributes()

print("set fan to FAN_SPEED_1")
device.set_fan_speed(FanSpeed.FAN_SPEED_1)
wait()
print_new_attributes()

print("frontal direction")
device.enable_frontal_direction()
wait()
print_new_attributes()

print("back direction")
device.disable_frontal_direction()
wait()
print_new_attributes()

print("off mode")
device.turn_off()
wait()
print_new_attributes()

print("script end")
device.disconnect()
