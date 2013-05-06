import numpy
import optparse
import pcap
import pygame
import struct
import sys
from scipy.interpolate import interp1d

sensor_w = 1436  # the packets all have 1436 bytes in them
sensor_linspace = numpy.linspace(0, sensor_w, sensor_w)
sensor_h = 1000 # This is all the more data we'll buffer

# Initial window size hardcoded to something small/reasonable
screen = pygame.display.set_mode((640, 480), pygame.RESIZABLE, 24)
screen.fill((0, 0, 0))
clock = pygame.time.Clock()

def num2gray(num):
    """Utility function for returning greyscale ints from numbers returned by
    ord when run against single characters 
    """
    return sum([num << x for x in range(0, 24, 8)])

def data_init(x, y):
    """ Utility function for initalizing data areas """
    return numpy.zeros((x, y), dtype=numpy.int8)


class View:
    """ A class to collect and render data from various sensors
    the hand argument is to deal with the case of the left-side sensor, its
    data comes in backwards where as the right-hand sensor requires no special
    handling
    """

    def __init__(self, width=640, height=480, hand='right'):
        self.surface = None
        self.init_surface(width, height)
        self.width = width
        self.newscale = numpy.linspace(0, sensor_w, width)
        self.height = height
        self.rawdata = data_init(sensor_w, sensor_h)
        self.rawy = sensor_h - 1
        self.viewdata = data_init(width, height)
        self.viewy = self.height - 1
        filler = num2gray(0)
        for x in xrange(self.width):
            for y in xrange(self.height):
                self.viewdata[x,y] = filler
        self.hand = hand

    def init_surface(self, x, y):
        """ Creates a new surface and sets the palette """
        self.surface = pygame.Surface((x, y), 0, 8)
        self.surface.set_palette([(c, c, c) for c in range(0, 256)])

    def resize(self, x, y):
        """Resizes the surface and the scaling factor for that surface"""
        self.init_surface(x, y)
        self.width = x
        self.newscale = numpy.linspace(0, sensor_w, x)
        self.height = y
        self.viewdata = data_init(x, y)
        self.rescale()

    def rescale(self):
        """Rescales all data lines onto newly resized surface"""
        for tmpi in range(self.height):
            self.viewdata[:,tmpi] = interp1d(sensor_linspace, 
                       self.rawdata.T[(self.rawy+tmpi)%sensor_h])(self.newscale)
        
        self.viewy = 0

    def new_line(self, line):
        """ Puts the newest line of data in the array, updates the y coord """
        if self.hand == 'left':
            line = line[::-1]
        for x, point in enumerate(line):
            self.rawdata[x, self.rawy] = num2gray(ord(point))
        self.viewdata[:,self.viewy] = interp1d(sensor_linspace,
                                       self.rawdata[:,self.rawy])(self.newscale)
        self.rawy  = (self.rawy  - 1) % sensor_h
        self.viewy = (self.viewy - 1) % self.height

    def draw(self):
        """Handles the rendering of the surface for this view. Data
        is scrolled once the buffer is filled by enough calls to new_line.
        The left-hand sensor is flipped accordingly
        """

        # This gives us a constant scroll effect, new data always appears
        # at the top, shifting everything down
        pygame.surfarray.blit_array(self.surface,
                 numpy.roll(self.viewdata, self.height-self.viewy-1, axis=1))


class DownView(View):
    """ Class to handle the down-only view, inherrits from the regular View
    class but has to do things a little differently
    """

    def __init__(self, width=640, height=480):
        View.__init__(self, width, height)
        self.rawx = sensor_h
        self.viewx = width - 1
        self.newscale = numpy.linspace(0, sensor_h, height)

    def resize(self, x, y):
        """Resizes the surface and the scaling factor for that surface"""
        self.init_surface(x, y)
        self.width = x
        self.newscale = numpy.linspace(0, sensor_w, x)
        self.height = y
        self.viewdata = data_init(x, y)

        self.newscale = numpy.linspace(0, sensor_h, y)

        self.rescale()

    def rescale(self):
        """Rescales all data lines onto newly resized surface"""
        tmpi = 0
        for tmpi in range(self.width):
            self.viewdata[tmpi,:] = interp1d(sensor_linspace, 
                       self.rawdata.T[(self.rawy+tmpi)%sensor_h])(self.newscale)
        
        self.viewx = 0


    def new_line(self, line):
        """ Puts the newest line of data in the array
        updates the x and y coord
        """

        for x, point in enumerate(line):
            self.rawdata[x, self.rawy] = num2gray(ord(point))
        self.viewdata[self.viewx,:] = interp1d(sensor_linspace,
                                       self.rawdata[:,self.rawy])(self.newscale)
        self.rawy = (self.rawy - 1) % sensor_h
        self.viewx = (self.viewx - 1) % self.width

    def draw(self):
        """Handles the rendering of the surface for this view. Data
        is scrolled once the buffer is filled by enough calls to new_line.
        """
        pygame.surfarray.blit_array(self.surface,
                 numpy.roll(self.viewdata, self.width-self.viewx-1, axis=0))


# printable character mapping for hex dumping
FILTER = ''.join([(len(repr(chr(i)))==3) and chr(i) or '.' for i in range(256)])

def dump2(src, length=16):
    """Utility function to print hex dumps"""
    result = []
    for idx in xrange(0, len(src), length):
        s = src[idx:idx+length]
        hexa = ' '.join(['%02X' % ord(x) for x in s])
        printable = s.translate(FILTER)
        result.append('%04X   %-*s   %s\n' % (idx, length*3, hexa, printable))
    return ''.join(result)


surfaces = None
def main(opts, args):
    global surfaces
    global screen
    infile = args[1]
    pkts = opts.count
    screeninfo = pygame.display.Info()
    screenh = screeninfo.current_h
    screenw = screeninfo.current_w

    packets = pcap.open(file(infile))
    sensed = 0
    surfaces = {'left':View(hand='left'), 'right':View(), 'down':DownView()}
    inview = 'right'
    for _, pktdata in packets:
        pkts -= 1
        # Skip the ip header
        _ = pktdata[:42]
        pktdata = pktdata[42:]
        dataheader = pktdata[:21]
        pktdata = pktdata[21:]
        #print dump2(dataheader)
        if not dataheader:
            continue

        if dataheader[0] == struct.pack('B', 0x21) :
            sensor = None
            if dataheader[1] == struct.pack('B', 0x02):
                sensor = 'down'
                sensed += 1
            elif dataheader[1] == struct.pack('B', 0x03):
                sensor = 'left'
                sensed += 1
            elif dataheader[1] == struct.pack('B', 0x04):
                sensor = 'right'
                sensed += 1

            data = pktdata[4:]
            if sensor:
                surfaces[sensor].new_line(data)
            else:
                print dump2(pktdata)
                continue
        else:
            continue

        if sensed > 2:
            sensed = 0
            if inview != 'all':
                surfaces[inview].draw()
                screen.blit(surfaces[inview].surface, (0, 0))
            else:
                offset = 0
                for view in ['left', 'right', 'down']:
                    surfaces[view].draw()
                    screen.blit(surfaces[view].surface, (offset, 0))
                    offset += screenw/3
                    
            clock.tick() 
            pygame.display.update()

        for event in pygame.event.get():
            setviewall = False
            setviewone = False
            if event.type == pygame.QUIT:
                return
            elif event.type == pygame.KEYDOWN:
                if event.key == pygame.K_ESCAPE:
                    return
                elif event.key == pygame.K_LEFT:
                    if inview == 'all':
                        setviewone = True
                    inview = 'left'
                elif event.key == pygame.K_RIGHT:
                    if inview == 'all':
                        setviewone = True
                    inview = 'right'
                elif event.key == pygame.K_DOWN:
                    if inview == 'all':
                        setviewone = True
                    inview = 'down'
                elif event.key == pygame.K_UP:
                    setviewall = True
                    if inview != 'all':
                        inview = 'all'
            elif event.type == pygame.VIDEORESIZE:
                print "RESIZE"
                screenw, screenh = event.dict['size']
                screen = pygame.display.set_mode((screenw, screenh),
                                                 pygame.RESIZABLE)
                if inview == 'all':
                    setviewall = True
                else:
                    setviewone = True
                print screeninfo.current_w, screeninfo.current_h

            if setviewall:
                for view in ['left','right']:
                    surfaces[view].resize(screenw/3, screenh)
                surfaces['down'].resize(screenw/2, screenh)
            if setviewone:
                for view in ['left', 'right', 'down']:
                    surfaces[view].resize(screenw, screenh)

        if pkts == 0:
            return

if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option('-c', '--count', default=-1, action='store', type='int',
                      help='Packets to read from a pcap file before exiting')

    options, arguments = parser.parse_args(sys.argv)
    main(options, arguments)
    print clock.get_fps()
