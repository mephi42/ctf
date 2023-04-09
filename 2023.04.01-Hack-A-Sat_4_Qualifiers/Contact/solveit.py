#!/usr/bin/env python3
from random import shuffle

import pygad
from skyfield.api import load
from skyfield.iokit import parse_tle_file
from skyfield.toposlib import wgs84

TIMESCALE = load.timescale()

# https://en.wikipedia.org/wiki/Two-line_element_set#Line_2
(ISS,) = parse_tle_file(
    b"""\
ISS (ZARYA)
1 25544U 98067A   08264.51782528 -.00002182  00000-0 -11606-4 0  2927
2 25544  51.6416 247.4627 0006703 130.5360 325.0288 15.72125391563537
""".split(
        b"\n"
    ),
    TIMESCALE,
)

# ticket{charlie415748delta4:GICM6RK1tf4NRcU2MifHgYsfevrgwytiUFGIZF3U08HExL7Ykq9t_UgpBjrXgoRZAQ}
# flag{charlie415748delta4:GDjRriDPG2pLylbFtfiKwG-IW2UrEhS8ed7Zmg6XRSSsnaPprDwzQObWs7e3MNdpHkmJzRlDXicweKhk3QDORVE}
(SOLUTION,) = parse_tle_file(
    b"""\
HACKASAT
1 75001F 23750A   23091.00000000  .00000000  00000-0  00000-0 0     1
2 75001  55.0000  12.4383 2113634 284.9109  63.6805 10.61411592000000
""".split(
        b"\n"
    ),
    TIMESCALE,
)

NETWORK = [
    wgs84.latlon(28.40, -80.61, 27),  # Cape Canaveral
    wgs84.latlon(41.70, -70.03, 9),  # Cape Cod
    wgs84.latlon(61.21, -149.90, 40),  # Anchorage
    wgs84.latlon(34.76, -120.52, 122),  # Vandenberg
    wgs84.latlon(39.74, -104.98, 1594),  # Denver
]


def calc(satellite):
    differences = [satellite - station for station in NETWORK]
    n = 0
    step_minutes = 1
    for hour in range(8):
        for minute in range(0, 60, step_minutes):
            t = TIMESCALE.utc(2023, 4, 1, hour, minute, 0)
            # https://rhodesmill.org/skyfield/coordinates.html#geographic-itrs-latitude-and-longitude
            satellite_pos = satellite.at(t)
            satellite_height = wgs84.height_of(satellite_pos)
            if satellite_height.km < 300:
                # Your satellite burned up in the atmosphere!! Keep it above 300km.
                return 0
            # https://rhodesmill.org/skyfield/earth-satellites.html#satellite-altitude-azimuth-and-distance
            for difference in differences:
                topocentric = difference.at(t)
                # https://rhodesmill.org/skyfield/positions.html#azimuth-and-altitude-from-a-geographic-position
                # Altitude measures the angle above or below the horizon.
                alt, _, distance = topocentric.altaz()
                if alt.degrees >= 15 and distance.km <= 6000:
                    n += step_minutes
                    break
    return n


def try_known():
    stations_url = "http://celestrak.org/NORAD/elements/gp.php?GROUP=active&FORMAT=tle"
    satellites = load.tle_file(stations_url)
    shuffle(satellites)
    best = None
    best_value = 0
    for satellite in satellites:
        value = calc(satellite)
        print(satellite.name)
        print(value)
        if value > best_value:
            best = satellite
            best_value = value
        if value >= 230:
            break
    print("===")
    print(best.name)
    print(best.value)


def try_gad():
    # https://pygad.readthedocs.io/en/latest/

    def fitness_function(x, _):
        tle = f"""\
HACKASAT
1 75001F 23750A   23091.00000000  .00000000  00000-0  00000-0 0     1
2 75001  {abs(x[0]*360):7.04f} {abs(x[1])*360:8.04f} {abs(int(x[2]*9999999)):07d} {abs(x[3]*360):8.04f} {abs(x[4]*360):8.04f} {abs(x[5]*24):11.08f}000000"""
        print(tle)
        (satellite,) = parse_tle_file(tle.encode().split(b"\n"))
        value = calc(satellite)
        print(value)
        if value >= 230:
            raise Exception("done")
        return value

    ga_instance = pygad.GA(
        num_generations=500,
        num_parents_mating=4,
        fitness_func=fitness_function,
        initial_population=(
            (
                51.6416 / 360,
                247.4627 / 360,
                6703 / 9999999,
                130.536 / 360,
                325.0288 / 360,
                15.72125391 / 24,
            ),
            (
                0.8538 / 360,
                210.5064 / 360,
                54388 / 9999999,
                79.9755 / 360,
                289.9129 / 360,
                1.09425897 / 24,
            ),
            (
                45.0148 / 360,
                266.9129 / 360,
                6382 / 9999999,
                97.8475 / 360,
                262.3099 / 360,
                14.40454716 / 24,
            ),
            (
                98.1004 / 360,
                162.207 / 360,
                837 / 9999999,
                7.2723 / 360,
                108.0077 / 360,
                14.59141836 / 24,
            ),
            (
                43.4239 / 360,
                75.3489 / 360,
                2128297 / 9999999,
                301.0016 / 360,
                491.9232 / 360,
                13.24455072 / 24,
            ),
            (
                43.4239 / 360,
                75.3489 / 360,
                3662629 / 9999999,
                301.0016 / 360,
                1262.6069 / 360,
                17.88359488 / 24,
            ),
            (
                43.4239 / 360,
                75.3489 / 360,
                5811009 / 9999999,
                259.4555 / 360,
                320.9141 / 360,
                14.18973638 / 24,
            ),
            (
                55 / 360,
                28 / 360,
                4 / 9999999,
                40 / 360,
                300 / 360,
                8.5 / 24,
            ),
            (
                55 / 360,
                39.1524 / 360,
                1853825 / 9999999,
                644.9109 / 360,
                1157.1003 / 360,
                9.99162081 / 24,
            ),
            (
                55 / 360,
                374.2451 / 360,
                2113634 / 9999999,
                644.9109 / 360,
                96.365 / 360,
                7.94037414 / 24,
            ),
            (
                55 / 360,
                374.2451 / 360,
                2113634 / 9999999,
                644.9109 / 360,
                1580.4853 / 360,
                9.99162081000000 / 24,
            ),
        ),
    )
    ga_instance.run()
    solution, solution_fitness, solution_idx = ga_instance.best_solution()
    print((solution, solution_fitness, solution_idx))


def main():
    print(calc(SOLUTION))


if __name__ == "__main__":
    main()
