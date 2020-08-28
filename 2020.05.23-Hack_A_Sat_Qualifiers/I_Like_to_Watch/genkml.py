#!/usr/bin/env python3
import numpy as np
from pwn import *
from skyfield.api import EarthSatellite, load, Topos
from skyfield.constants import AU_M, DEG2RAD, RAD2DEG
from skyfield.earthlib import terra

io = remote('watch.satellitesabove.me', 5011)
io.recvuntil('Ticket please:')
io.sendline('ticket{papa5653yankee:GA68ruoNNROVxT_mabOmNAro_Sjv2_IHlCjzcHpbyZKFAbsTSkQziRed-WFC1COCVg}')
io.recvuntil('REDACT\n')
line1 = io.recvline().decode().strip()
line2 = io.recvline().decode().strip()
assert line1 == '1 13337U 98067A   20087.38052801 -.00000452  00000-0  00000+0 0  9995'
assert line2 == '2 13337  51.6460  33.2488 0005270  61.9928  83.3154 15.48919755219337'
io.recvuntil('Use a Google Earth Pro KML file to \'Link\' to ')
url = io.recvline().decode().strip()


def angle(v1, v2):
    uv1 = v1 / np.linalg.norm(v1)
    uv2 = v2 / np.linalg.norm(v2)
    return np.arccos(np.dot(uv1, uv2)) * RAD2DEG


ts = load.timescale()
satellite = EarthSatellite(line1, line2, 'I Like to Watch', ts)
print(f'{satellite=}')
t = ts.utc(2020, 3, 26, 21, 52, 43)  # March 26th, 2020, at 21:52:43
geocentric = satellite.at(t)
print(f'{ geocentric.position.m=}')
subpoint = geocentric.subpoint()
print(f'{subpoint.latitude.degrees=}')
print(f'{subpoint.longitude.degrees=}')
print(f'{subpoint.elevation.m=}')
same_pos, same_vel = terra(
    subpoint.latitude.radians,
    subpoint.longitude.radians,
    subpoint.elevation.au,
    geocentric.t.gast,
)
same_pos *= AU_M
print(f'{same_pos=}')
monument = Topos('38.8894541 N', '77.0373601 W')
print(f'{monument=}')
monument_pos, _ = terra(
    monument.latitude.radians,
    monument.longitude.radians,
    0,
    geocentric.t.gast,
)
monument_pos *= AU_M
print(f'{monument_pos=}')
# range = np.linalg.norm(geocentric.position.m - monument_pos)
# tilt = angle(geocentric.position.m - monument_pos, monument_pos)
north_pole_pos, _ = terra(
    90 * DEG2RAD,
    135 * DEG2RAD,
    0,
    geocentric.t.gast,
)
north_pole_pos *= AU_M
print(f'{north_pole_pos=}')
satellite_projection_pos, _ = terra(
    subpoint.latitude.radians,
    subpoint.longitude.radians,
    0,
    geocentric.t.gast,
)
satellite_projection_pos *= AU_M
print(f'{satellite_projection_pos=}')

look = satellite - monument
print(f'{look=}')
look_at_t = look.at(t)
alt, az, distance = look_at_t.altaz()
tilt = 90 - alt.degrees
heading = az.degrees - 180
range = distance.m

with open('example.kml', 'w') as fp:
    fp.write(f'''<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
  <Folder>
    <name>HackASatCompetition</name>
    <visibility>0</visibility>
    <open>0</open>
    <description>HackASatComp1</description>
    <NetworkLink>
      <name>View Centered Placemark</name>
      <visibility>0</visibility>
      <open>0</open>
      <description>This is where the satellite was located when we saw it.</description>
      <refreshVisibility>0</refreshVisibility>
      <flyToView>0</flyToView>
      <LookAt id="ID">
        <!-- specific to LookAt -->
        <longitude>{monument.longitude.degrees}</longitude>            	<!-- kml:angle180 -->
        <latitude>{monument.latitude.degrees}</latitude>              	<!-- kml:angle90 -->
        <altitude>0</altitude>              		<!-- double -->
        <heading>{heading}</heading>                <!-- kml:angle360 -->
        <tilt>{tilt}</tilt>                     <!-- kml:anglepos90 -->
        <range>{range}</range>                     <!-- double -->
        <altitudeMode>clampToGround</altitudeMode>
      </LookAt>
      <Link>
        <href>{url}</href>
        <refreshInterval>1</refreshInterval>
        <viewRefreshMode>onStop</viewRefreshMode>
        <viewRefreshTime>1</viewRefreshTime>
        <viewFormat>BBOX=[bboxWest],[bboxSouth],[bboxEast],[bboxNorth];CAMERA=[lookatLon],[lookatLat],[lookatRange],[lookatTilt],[lookatHeading];VIEW=[horizFov],[vertFov],[horizPixels],[vertPixels],[terrainEnabled]</viewFormat>
      </Link>
    </NetworkLink>
  </Folder>
</kml>
''')
io.interactive()
