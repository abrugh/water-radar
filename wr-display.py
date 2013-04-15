import collections
import numpy
import optparse
import pcap
import pygame
import struct
import sys

w = 1436  # the packets all have 1436 bytes in them
h = 768   # This is all the more data we'll buffer

# Initial window size hardcoded to something small/reasonable
screen = pygame.display.set_mode((640, 480), pygame.RESIZABLE)
screen.fill((255,255,255))
clock = pygame.time.Clock()

def num2gray(n):
    """Utility function for returning greyscale ints from numbers returned by
    ord when run against single characters 
    """
    return sum([n << x for x in range(0,24,8)])

class View:
    """ A class to collect and render data from various sensors
    the hand argument is to deal with the case of the left-side sensor, its
    data comes in backwards where as the right-hand sensor requires no special
    handling
    """

    def __init__(self, height=h, width=w, hand="right"):
        self.surface = pygame.Surface((width, height), 0, 24)
        self.height = height
        self.width = width
        self.data = numpy.zeros((width,height), dtype=numpy.int32)
        filler = num2gray(255)
        for x in xrange(w):
            for y in xrange(h):
                self.data[x,y] = filler
        self.hand = hand
        self.y = height - 1
        self.roll = False

    def new_line(self, line):
        """ Puts the newest line of data in the array, updates the y coord """
        for x, point in enumerate(line):
            self.data[x,self.y] = num2gray(ord(point))
        self.y = (self.y - 1)
        if self.y == -1:
            self.y = self.height - 1
            self.roll = True

    def draw(self):
        """Handles the rendering of the surface for this view. Data
        is scrolled once the buffer is filled by enough calls to new_line
        and the left-hand sensor is flipped accordingly
        """

        # This gives us a constant scroll effect, new data always appears
        # at the top, shifting everything down
        pygame.surfarray.blit_array(self.surface,
                         numpy.roll(self.data, self.height-self.y-1, axis=1))
        if self.hand == 'left':
            pygame.transform.flip(self.surface, True, False)
        

# printable character mapping for hex dumping
FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])

def dump2(src, length=16):
    """Utility function to print hex dumps"""
    result=[]
    for i in xrange(0, len(src), length):
       s = src[i:i+length]
       hexa = ' '.join(["%02X"%ord(x) for x in s])
       printable = s.translate(FILTER)
       result.append("%04X   %-*s   %s\n" % (i, length*3, hexa, printable))
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
    surfaces = {"left":View(hand='left'), "right":View(), "down":[]}
    for bs, i in packets:
        pkts -= 1
        ipheader = i[:42]
        i = i[42:]
        dataheader = i[:21]
        i = i[21:]
        #print dump2(dataheader)
        if not dataheader:
            continue

        if dataheader[0] == struct.pack('B', 0x21) :
            sensor = None
            if dataheader[1] == struct.pack('B', 0x02):
                sensor = "down"
                sensed += 1
            elif dataheader[1] == struct.pack('B', 0x03):
                sensor = "left"
                sensed += 1
            elif dataheader[1] == struct.pack('B', 0x04):
                sensor = "right"
                sensed += 1

            #print dump2(i)
            data = i[4:]
            if sensor in ["right","left"]:
                surfaces[sensor].new_line(data)
#            elif sensor == "down":
#                surfaces[sensor].append(pygame.Surface((1,400)))
#                for x, j in enumerate(data[4:h+4]):
#                    surfaces[sensor][-1].set_at((0,x),((ord(j),ord(j),ord(j))))
        if sensed > 2:
            sensed = 0
            surfaces["right"].draw()
            #screen.blit(surfaces["right"].surface, (0,0))
            # Scaling data to the window is super expensive (for netbooks)
            screen.blit(pygame.transform.smoothscale(surfaces["right"].surface,
                        (screenw, screenh)), (0,0))


    #        for sensor in ["left", "right"]:
    #            if sensor == "right":
    #                offset = w/3
    #            if len(surfaces[sensor]) > h:
    #                surfaces[sensor].pop(0) 
    #            for x,i in enumerate(surfaces[sensor][::-1]):
    #                if sensor == "left":
    #                    screen.blit(pygame.transform.flip(
#                           pygame.transform.smoothscale(i, (w/3, 1)), 1, 0), (offset,x))
    #                else:
    #                    screen.blit(pygame.transform.smoothscale(i,(w/3,1)), (offset,x))
    #        for sensor in ["down"]:
    #            offset = 2*(w/3)
    #            if len(surfaces[sensor]) > w/3:
    #                surfaces[sensor].pop(0)
    #            for x,i in enumerate(surfaces[sensor][::-1]):
    #                screen.blit(i,(w-x,0))

            pygame.display.update()
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                return
            elif event.type == pygame.KEYDOWN:
                if event.key == pygame.K_ESCAPE:
                    return
    #            elif event.key == pygame.K_LEFT:
    #            elif event.key == pygame.K_RIGHT:
            elif event.type == pygame.VIDEORESIZE:
                print "RESIZE"
                screenw, screenh = event.dict['size']
                screen = pygame.display.set_mode((screenw, screenh), pygame.RESIZABLE)
                print screeninfo.current_h, screeninfo.current_w

        #clock.tick(60) # commented out cuz my netbook can't keep up as is
        if pkts == 0:
            return

if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option("-c", "--count", default=-1, action="store", type="int",
                        help="Packets to read from a pcap file before exiting")

    options, arguments = parser.parse_args(sys.argv)
    main(options, arguments)

    # vars for debugging in interactive mode
    d = surfaces['right'].data
    s = surfaces['right'].surface
    y = surfaces['right'].y
