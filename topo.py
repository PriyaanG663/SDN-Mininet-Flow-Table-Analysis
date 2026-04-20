
from mininet.topo import Topo
class ProjectTopo(Topo):
    def build(self):
        s1, s2 = self.addSwitch('s1'), self.addSwitch('s2')
        h1, h2, h3 = self.addHost('h1'), self.addHost('h2'), self.addHost('h3')
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s2)
        self.addLink(s1, s2)
topos = {'project_topo': (lambda: ProjectTopo())}
