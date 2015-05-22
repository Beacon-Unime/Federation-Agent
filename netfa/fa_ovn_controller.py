from netfa.fa_sdn_controller import FaSdnController

class OvnController(FaSdnController):
    def initialize(self):
        return

    def __init__(self):
        super(OvnController, self).__init__()

    def test(self):
        print "test\n"
