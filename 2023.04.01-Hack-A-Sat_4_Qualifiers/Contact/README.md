# Contact (mini writeup)

* Given 5 ground stations, come up with an orbit, such that within an 8-hour
  period the satellite is in contact with at least one of them for 230 minutes.
* "In contact" means:
  * Within 6000 km.
  * Above 15 degrees above the horizon.
  * At least 300km above Earth.
* The output must be in TLE format.
* Step 1: simulate orbit with 1 minute granularity, which is close enough to the
  checker.
* Step 2: check if there is an actual satellite that already satisfies the
  criteria, or is at least close enough.
* Step 3: find an orbit using a genetic algorithm.
  * Use `pygad`.
  * Seed it with orbits from step 2.
  * Normalize parameters to a single-digit range.
