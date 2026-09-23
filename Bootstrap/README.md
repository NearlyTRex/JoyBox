# JoyBox Bootstrap

Sets up a machine in one command instead of remembering and installing everything by hand:
`local_ubuntu` for a desktop, `remote_ubuntu` for a server driven over SSH.

```bash
python3 bootstrap.py -a setup -t local_ubuntu
python3 bootstrap.py -a setup -t remote_ubuntu -s 0
python3 bootstrap.py -t local_ubuntu --list-components
```

- [Local Computer Setup](../Docs/setup/local-computer.md)
- [Remote Server Setup](../Docs/setup/remote-server.md)
- [Bootstrap Commands](../Docs/reference/bootstrap-commands.md)
- [Adding Software](../Docs/reference/adding-software.md)
- [All documentation](../Docs/README.md)
