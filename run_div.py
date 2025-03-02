from p4utils.mininetlib.network_API import NetworkAPI

net = NetworkAPI()


# Network general options
net.cleanup()
net.setLogLevel('info')
net.execScript('python controller_div.py',reboot=True)
# net.disableArpTables()


# Network definition
net.addP4Switch('s1')
net.setP4Source('s1','p4src/approximate_div.p4')
net.setP4CliInput('s1', './s1-commands.txt')
net.addHost('h1')
net.addHost('h2')
net.addLink('s1', 'h1')
net.addLink('s1', 'h2')


# Assignment strategy
net.l2()

# Nodes general options
# net.disablePcapDumpAll()
# net.disableLogAll()
net.enableLogAll()
net.enablePcapDumpAll()
net.enableCli()
net.startNetwork()