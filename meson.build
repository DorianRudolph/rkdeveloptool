project('rkdeveloptool', 'cpp', version: '1.0.0')

libusb = dependency('libusb-1.0')

conf = configuration_data()
conf.set_quoted('PACKAGE_VERSION', meson.project_version())
configure_file(
    output: 'config.h',
    configuration: conf
)

executable('rkdeveloptool',
    'main.cpp',
    'RKBoot.cpp',
    'RKComm.cpp',
    'RKDevice.cpp',
    'RKImage.cpp',
    'RKLog.cpp',
    'RKScan.cpp',
    'crc.cpp',
    dependencies: [libusb],
    install: true)


# Install udev rules for the usb part
udev = dependency('udev')
udev_rules_dir = udev.get_pkgconfig_variable('udevdir') + '/rules.d'
install_data(
    ['99-rk-rockusb.rules'],
    install_dir: udev_rules_dir,
)

# Build and install the man pages
scdoc = dependency('scdoc', native: true, required: get_option('man-pages'))
if scdoc.found()
  scdoc_prog = find_program(scdoc.get_pkgconfig_variable('scdoc'), native: true)
  sh = find_program('sh', native: true)
  mandir = get_option('mandir')
  man_files = [
            'doc/rkdeveloptool.1.scd',
  ]
  foreach filename : man_files
    topic = filename.split('.')[-3].split('/')[-1]
    section = filename.split('.')[-2]
    output = '@0@.@1@'.format(topic, section)

    custom_target(
      output,
      input: filename,
      output: output,
      command: [
        sh, '-c', '@0@ < @INPUT@ > @1@'.format(scdoc_prog.path(), output)
      ],
      install: true,
      install_dir: '@0@/man@1@'.format(mandir, section)
    )
  endforeach
endif