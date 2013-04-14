import collections
import numpy
import pcap
import pygame
import struct
import sys
w = 1436
h = 400
screen = pygame.display.set_mode((w, h))
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
        self.surface = pygame.Surface((width,height), 0, 8)
        self.height = height
        self.width = width
        self.data = numpy.zeros((width,height), dtype=int)
        filler = int2gray(255)
        for x in xrange(w):
            for y in xrange(h):
                self.data[x,y] = filler
        self.hand = hand
        self.y = height - 1
        self.roll = False

    def new_line(self, line):
        """ Puts the newest line of data in the array, updates the y coord """
        for x, point in enumerate(line):
            self.data[x,self.y] = ord(point) #((ord(point),ord(point),ord(point)))
        self.y = (self.y - 1)
        if self.y == -1:
            self.y = self.height - 1
            self.roll = True

    def draw(self):
        """Handles the rendering of the surface for this view. Data
        is scrolled once the buffer is filled by enough calls to new_line
        and the left-hand sensor is flipped accordingly
        """

        pygame.surfarray.blit_array(self.surface, numpy.roll(self.data, self.height-self.y-1, axis=1))
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

infile = sys.argv[1]
pkts = int(sys.argv[2])

packets = pcap.open(file(infile))
sensed = 0
surfaces = {"left":View(hand='left'),"right":View(),"down":[]}
for bs, i in packets:
    pkts -= 1
    ipheader = i[:42]
    i = i[42:]
    dataheader = i[:21]
    i = i[21:]
    #print dump2(dataheader)
    if not dataheader:
        continue

    if dataheader[0] == struct.pack('B',0x21) :
        sensor = None
        #down?
        if dataheader[1] == struct.pack('B', 0x02):
            sensor = "down"
            sensed += 1
        #left?
        elif dataheader[1] == struct.pack('B', 0x03):
            sensor = "left"
            sensed += 1
        #right?
        elif dataheader[1] == struct.pack('B', 0x04):
            sensor = "right"
            sensed += 1

        #print dump2(i)
        data = i[4:]
#        if sensor == "left":
#            data = data[::-1]
        if sensor in ["right","left"]:
            surfaces[sensor].new_line(data)
        elif sensor == "down":
            surfaces[sensor].append(pygame.Surface((1,400)))
            for x, j in enumerate(data[4:h+4]):
                surfaces[sensor][-1].set_at((0,x),((ord(j),ord(j),ord(j))))
    if sensed > 2:
        sensed = 0
        offset = 0
        surfaces["right"].draw()
        screen.blit(surfaces["right"].surface, (0,0))


#        for sensor in ["left", "right"]:
#            if sensor == "right":
#                offset = w/3
#            if len(surfaces[sensor]) > h:
#                surfaces[sensor].pop(0) 
#            for x,i in enumerate(surfaces[sensor][::-1]):
#                if sensor == "left":
#                    screen.blit(pygame.transform.flip(pygame.transform.smoothscale(i,(w/3,1)),1,0), (offset,x))
#                else:
#                    screen.blit(pygame.transform.smoothscale(i,(w/3,1)), (offset,x))
#        for sensor in ["down"]:
#            offset = 2*(w/3)
#            if len(surfaces[sensor]) > w/3:
#                surfaces[sensor].pop(0)
#            for x,i in enumerate(surfaces[sensor][::-1]):
#                screen.blit(i,(w-x,0))
#        
        pygame.display.update()
    #clock.tick(60)
    if pkts == 0:
        sys.exit(0)
