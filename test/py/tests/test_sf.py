# Copyright (c) 2017, Xiphos Systems Corp. All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0

import re
import pytest
import u_boot_utils


"""
Note: This test relies on boardenv_* containing configuration values to define
which spi flash areas are available for testing.  Without this, this test will
be automatically skipped.
For example:

# Boolean indicating whether the SF tests should be skipped.
env__sf_skip = False

# A list of sections of flash memory to be tested.
env__sf_configs = (
    {
        # Optional, [[bus:]cs] argument used in `sf probe`
        'id': "0",
        # Where in SPI flash should the test operate.
        'offset': 0x00000000,
        # This value is optional.
        #   If present, specifies the size to use for read/write operations.
        #   If missing, the SPI Flash page size is used as a default (based on
        #   the `sf probe` output).
        'len': 0x10000,
        # Specifies if the test can write to offset
        'writeable': False,
    },
)
"""


def sf_prepare(u_boot_console, env__sf_config, verbose=False):
    """Check global state of the SPI Flash before running any test.

   Args:
        u_boot_console: A U-Boot console connection.
        env__sf_config: The single SPI flash device configuration on which to
            run the tests.

    Returns:
        Nothing.
    """

    if u_boot_console.config.env.get('env__sf_skip', True):
        pytest.skip('sf test disabled in environment')

    # NOTE: sf read at address 0 fails because map_physmem 'converts' it
    #       address 0 to a pointer.
    ram_address = u_boot_utils.find_ram_base(u_boot_console) + 0x10

    probe_id = env__sf_config.get('id', '')
    output = u_boot_console.run_command('sf probe ' + probe_id)
    if 'SF: Detected' not in output:
        pytest.fail('No flash device available')

    m = re.search('page size (.+?) Bytes', output)
    if m:
        try:
            page_size = int(m.group(1))
        except ValueError:
            pytest.fail('SPI Flash page size not recognized')

    m = re.search('erase size (.+?) KiB', output)
    if m:
        try:
            erase_size = int(m.group(1))
        except ValueError:
            pytest.fail('SPI Flash erase size not recognized')

        erase_size *= 1024

    m = re.search('total (.+?) MiB', output)
    if m:
        try:
            total_size = int(m.group(1))
        except ValueError:
            pytest.fail('SPI Flash total size not recognized')

        total_size *= 1024 * 1024

    if verbose:
        u_boot_console.log.info('Page size is: ' + str(page_size) + ' B')
        u_boot_console.log.info('Erase size is: ' + str(erase_size) + ' B')
        u_boot_console.log.info('Total size is: ' + str(total_size) + ' B')

    env__sf_config['len'] = env__sf_config.get('len', erase_size)
    if env__sf_config['offset'] % erase_size or \
            env__sf_config['len'] % erase_size:
        u_boot_console.log.warning("erase offset/length not multiple of "
                                   "erase size")

    env__sf_config['ram_address'] = ram_address


def crc32(u_boot_console, address, count):
    """Helper function used to compute the CRC32 value of a section of RAM.

    Args:
        u_boot_console: A U-Boot console connection.
        address: Address where data starts.
        count: Amount of data to use for calculation.

    Returns:
        CRC32 value
    """

    output = u_boot_console.run_command('crc32 %08x %x' % (address, count))

    m = re.search('==> ([0-9a-fA-F]{8})$', output)
    if not m:
        pytest.fail('CRC32 failed')

    return m.group(1)


def sf_read(u_boot_console, env__sf_config, size=None):
    """Helper function used to read and compute the CRC32 value of a section of
    SPI Flash memory.

    Args:
        u_boot_console: A U-Boot console connection.
        env__sf_config: The single SPI flash device configuration on which to
            run the tests.
        size: Optional, used to override env__sf_config value.

    Returns:
        CRC32 value of SPI Flash section
    """

    if size is None:
        size = env__sf_config['len']

    u_boot_console.run_command('mw %08x 0 %x' % (env__sf_config['ram_address'],
                                                 size))

    response = u_boot_console.run_command('sf read %08x %08x %x' %
                                          (env__sf_config['ram_address'],
                                           env__sf_config['offset'],
                                           size))
    assert 'Read: OK' in response, "Read operation failed"

    return crc32(u_boot_console, env__sf_config['ram_address'],
                 env__sf_config['len'])


def sf_update(u_boot_console, env__sf_config):
    """Helper function used to update a section of SPI Flash memory.

   Args:
        u_boot_console: A U-Boot console connection.
        env__sf_config: The single SPI flash device configuration on which to
           run the tests.

    Returns:
        CRC32 value of SPI Flash section
    """
    from time import time

    u_boot_console.run_command('mw %08x %08x %x' %
                               (env__sf_config['ram_address'], time(),
                                env__sf_config['len']))
    crc_ram = crc32(u_boot_console, env__sf_config['ram_address'],
                    env__sf_config['len'])
    u_boot_console.run_command('sf update %08x %08x %x' %
                               (env__sf_config['ram_address'],
                                env__sf_config['offset'],
                                env__sf_config['len']))

    crc2 = sf_read(u_boot_console, env__sf_config)

    return (crc2 == crc_ram)


@pytest.mark.buildconfigspec("cmd_sf")
def test_sf_read(u_boot_console, env__sf_config):
    sf_prepare(u_boot_console, env__sf_config)

    output = u_boot_console.run_command('sf read %08x %08x %x' %
                                        (env__sf_config['ram_address'],
                                         env__sf_config['offset'],
                                         env__sf_config['len']))
    assert 'Read: OK' in output, "Read operation failed"


@pytest.mark.buildconfigspec("cmd_sf")
@pytest.mark.buildconfigspec("cmd_crc32")
@pytest.mark.buildconfigspec("cmd_memory")
def test_sf_read_twice(u_boot_console, env__sf_config):
    sf_prepare(u_boot_console, env__sf_config)

    crc1 = sf_read(u_boot_console, env__sf_config)
    crc2 = sf_read(u_boot_console, env__sf_config)

    assert crc1 == crc2, "CRC32 of two successive read operation do not match"


@pytest.mark.buildconfigspec("cmd_sf")
@pytest.mark.buildconfigspec("cmd_crc32")
@pytest.mark.buildconfigspec("cmd_memory")
def test_sf_erase(u_boot_console, env__sf_config):
    if not env__sf_config['writeable']:
        pytest.skip('flash config is tagged as not writeable')

    sf_prepare(u_boot_console, env__sf_config)
    output = u_boot_console.run_command('sf erase %08x %x' %
                                        (env__sf_config['offset'],
                                         env__sf_config['len']))
    assert 'Erased: OK' in output, "Erase operation failed"

    u_boot_console.run_command('mw %08x ffffffff %x' %
                               (env__sf_config['ram_address'],
                                env__sf_config['len']))
    crc1 = crc32(u_boot_console, env__sf_config['ram_address'],
                 env__sf_config['len'])

    crc2 = sf_read(u_boot_console, env__sf_config)
    assert crc1 == crc2, "CRC32 of erase section does not match expected value"


@pytest.mark.buildconfigspec("cmd_sf")
@pytest.mark.buildconfigspec("cmd_memory")
def test_sf_update(u_boot_console, env__sf_config):
    if not env__sf_config['writeable']:
        pytest.skip('flash config is tagged as not writeable')

    sf_prepare(u_boot_console, env__sf_config)
    assert sf_update(u_boot_console, env__sf_config) is True
