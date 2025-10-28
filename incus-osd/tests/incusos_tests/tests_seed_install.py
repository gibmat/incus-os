import os
import subprocess
import tempfile
import time

from .incus_test_vm import IncusTestVM, util

def TestSeedInstallReboot(install_image):
    test_name = "seed-install-reboot"
    test_seed = {
        "install.json": """{"force_reboot":true}"""
    }

    test_image, incusos_version = util._prepare_test_image(install_image, test_seed)

    with IncusTestVM(test_name, test_image) as vm:
        # Perform IncusOS install.
        vm.StartVM()
        vm.WaitAgentRunning()
        vm.WaitExpectedLog("incus-osd", "Installing IncusOS source=/dev/sdb target=/dev/sda")
        vm.WaitExpectedLog("incus-osd", "IncusOS was successfully installed")

        # Wait for the VM to auto-reboot.
        time.sleep(15)

        # Since we don't remove the install media, expect an error which is fine for this test.
        vm.WaitAgentRunning()
        vm.WaitExpectedLog("incus-osd", "System check error: install media detected, but the system is already installed; please remove USB/CDROM and reboot the system")

def TestSeedInstallTarget(install_image):
    test_name = "seed-install-target"
    test_seed = {
        "install.json": """{"target":{"id":"scsi-0QEMU_QEMU_HARDDISK_incus_root"}}"""
    }

    test_image, incusos_version = util._prepare_test_image(install_image, test_seed)

    with tempfile.NamedTemporaryFile(dir=os.getcwd()) as disk_img:
        with IncusTestVM(test_name, test_image) as vm:
            vm.AddDevice("disk1", "disk", "source="+disk_img.name)

            # Perform IncusOS install.
            vm.StartVM()
            vm.WaitAgentRunning()
            vm.WaitExpectedLog("incus-osd", "Installing IncusOS source=/dev/sdc target=/dev/sda", regex=True)
            vm.WaitExpectedLog("incus-osd", "IncusOS was successfully installed")

def TestSeedInstallForce(install_image):
    test_name = "seed-install-force"
    test_seed = {
        "install.json": """{"target":{"id":"scsi-0QEMU_QEMU_HARDDISK_incus_disk1"},"force_install":true}"""
    }

    test_image, incusos_version = util._prepare_test_image(install_image, test_seed)

    with tempfile.NamedTemporaryFile(dir=os.getcwd()) as disk_img:
        # Truncate the disk image file to 50GiB and setup a single GPT partition.
        # The presence of the existing GPT table will cause install to fail unless
        # "ForceInstall" is set to true.
        disk_img.truncate(50*1024*1024*1024)
        subprocess.run(["/sbin/sgdisk", "-n", "1", disk_img.name], capture_output=True, check=True)

        with IncusTestVM(test_name, test_image) as vm:
            vm.AddDevice("disk1", "disk", "source="+disk_img.name)

            # Perform IncusOS install.
            vm.StartVM()
            vm.WaitAgentRunning()
            vm.WaitExpectedLog("incus-osd", "Installing IncusOS source=/dev/sdc target=/dev/sdb", regex=True)
            vm.WaitExpectedLog("incus-osd", "IncusOS was successfully installed")
