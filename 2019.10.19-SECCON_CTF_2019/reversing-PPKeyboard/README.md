# Reversing - PPKeyboard

We are given a Windows application and a `.pcapng` packet capture. Running the
application under `wine` produces a warning about unimplemented `MIDI`
functionality, after which the application exits. A quick look with IDA reveals
that the application insists on talking to a cool `DDJ-XP1` DJ pad, which is
split in two 16-button halves. `.pcapng` contains a bunch of USB packets flying
in both directions, which must be key presses.

Dumping it with `pyshark` reveals the following repeating pattern:

```
1.7.4 -> host: 09:97:04:7f
host -> 1.7.4:
1.7.4 -> host: 09:97:04:00
host -> 1.7.4:
1.7.4 -> host: 09:99:08:7f
host -> 1.7.4:
1.7.4 -> host: 09:99:08:00
host -> 1.7.4:
```

`1.7.4 -> host` messages look like ACKs, let's get rid of them:

```
1.7.4 -> host: 09:97:04:7f
1.7.4 -> host: 09:97:04:00
1.7.4 -> host: 09:99:08:7f
1.7.4 -> host: 09:99:08:00
```

The messages ending with `:00` must be key releases, which leaves us with:

```
1.7.4 -> host: 09:97:04:7f
1.7.4 -> host: 09:99:08:7f
```

The pattern always alternates between `97` and `99`, which most likely means
that DJ was pressing first the button on the left half, and then the button
on the right half. `04` and `08` must be button codes.

Frequency analysis (1-grams, 2-grams) does not produce any results, but the
message is fairly short, so it's probably okay. Key press durations are all over
the place, so this can't be Morse code.

One could notice though that 0x04 and 0x08 can be concatenated to 0x48, which is
the ASCII code for the letter 'H'. This way the entire message can be
deciphered:

```
Hey guys! FLAG is SECCON{3n73r3d_fr0m_7h3_p3rf0rm4nc3_p4d_k3yb04rd}
```

P.S. Of course, [turns out](
https://tuanlinh.gitbook.io/ctf/seccon-2019-qualification#ppkeyboard
) it's not necessary to resort to guessing to solve this task. One could simply
use the brain, read the `midiInOpen` manual, reverse engineer the callback
that's passed to it, and figure out the logic explained above. But why would
anyone in their mind do that? /s
