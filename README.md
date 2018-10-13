# CirrusScan check

CirrusScan will run checks against the AWS infrastructure using configuration
data contained within this directory hierarchy.  Each check is self contained,
and has its configuration data defined in a separate subdirectory.  An
arbitrary directory structure may be constructed under the `checks`
subdirectory in this repo.

## Configuration

Configuration may be specified via one or more JSON or YAML files that are
suffixed with a `.json` or `.yaml` file extension, respectively.

*TODO: describe format of configuration files*

## Scheduling

*TODO: describe when/how checks are scheduled*

## Execution

*TODO: describe when/how checks are executed*

## Reporting

*TODO: describe how and where check results are reported*

