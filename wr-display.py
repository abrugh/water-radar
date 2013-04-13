import pcap
import sys
import struct
import pygame
w = 1200
h = 400
screen = pygame.display.set_mode((w, h))
screen.fill((255,255,255))
clock = pygame.time.Clock()

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
surfaces = {"left":[],"right":[],"down":[]}
for bs, i in packets:
    pkts -= 1
    ipheader = i[:42]
    i = i[42:]
    dataheader = i[:21]
    i = i[21:]
    #print dump2(dataheader)

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
#        data = i[4:(w/3)+4]
        data = i[4:]
#        if sensor == "left":
#            data = data[::-1]
        if sensor in ["right","left"]:
            surfaces[sensor].append(pygame.Surface((1400,1)))
            for x,j in enumerate(data):
                surfaces[sensor][-1].set_at((x,0),(ord(j),ord(j),ord(j)))
        elif sensor == "down":
            surfaces[sensor].append(pygame.Surface((1,400)))
            for x, j in enumerate(data[4:h+4]):
                surfaces[sensor][-1].set_at((0,x),((ord(j),ord(j),ord(j))))
    if sensed > 2:
        sensed = 0
        offset = 0
        for sensor in ["left", "right"]:
            if sensor == "right":
                offset = w/3
            if len(surfaces[sensor]) > h:
                surfaces[sensor].pop(0) 
            for x,i in enumerate(surfaces[sensor][::-1]):
                if sensor == "left":
                    screen.blit(pygame.transform.flip(pygame.transform.smoothscale(i,(w/3,1)),1,0), (offset,x))
                else:
                    screen.blit(pygame.transform.smoothscale(i,(w/3,1)), (offset,x))
        for sensor in ["down"]:
            offset = 2*(w/3)
            if len(surfaces[sensor]) > w/3:
                surfaces[sensor].pop(0)
            for x,i in enumerate(surfaces[sensor][::-1]):
                screen.blit(i,(w-x,0))
        
        pygame.display.update()
    #clock.tick(60)
    if pkts == 0:
        sys.exit(0)
