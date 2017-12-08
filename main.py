from engine.Engine import Engine
from ui.ti import Ti
import sys

class PacketInjector(object):
    def __init__(self, engine, ui):
        self.engine = engine
        self.ui = ui
    
    def run(self):
        newPacket = True
        while True:
            if newPacket:
                self.engine.initPacket()
            config, info, send = self.ui.getInput()
            self.engine.updateConfig(config)
            self.engine.updateInfo(info)
            if send:
                self.engine.sendPacket()
                newPacket = True
            else:
                newPacket = False
        sys.exit(0)

def main():
    app = PacketInjector(Engine(), Ti())
    return(app.run())

if __name__ == '__main__':
    main()