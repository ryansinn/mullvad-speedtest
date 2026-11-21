# mvbench

Surveys Mullvad WireGuard exits and keeps every result. A run measures Sweden first, then one relay in each North America city, best-rated relays first. Speed or ping far from that run's pack, or far from the relay's own average, is tested once more at the end. A relay whose past results already look like this one is left alone, so a distant city is confirmed once instead of retested forever. Both results are stored. If they agree, the relay is consistent. If they don't, it is marked a fluke and left out of the ranking.

`./mvbench.py patterns` shows the overall average and each relay's average speed and ping.

    ./mvbench.py plan        # the batch, without switching the tunnel
    ./mvbench.py run         # about 10 minutes. Switches the live tunnel.
    ./mvbench.py watch       # live progress in this terminal until the run finishes

`run` owns the tunnel until it finishes, then puts the previous relay constraint back. In a terminal it draws the live view itself. From a service, or any time you want a second window:

    ./mvbench.py watch

The view shows progress, the Sweden benchmark, and the fastest and slowest North America results so far. Ctrl-C in the watch window only stops watching.

    ./mvbench.py report      # per-relay stats for the last 14 days
    ./mvbench.py patterns    # all stored tests, by country, city, and relay
    ./mvbench.py recommend   # the ordered list apply will load
    ./mvbench.py apply       # load that list into Mullvad and make it the active constraint
    ./mvbench.py apply --pin # use only the top relay
    ./mvbench.py connect     # connect to the top relay once

Mullvad's Linux client can load a custom list and stay inside it. The client then chooses among those relays itself. It does not follow the list as a priority queue. `apply` still adds them best-first. `--pin` locks the single best relay when that matters more than a pool.

    ./mvbench.py restore     # put the pre-run constraint back if a run was killed
    ./mvbench.py block add us-mia-* --reason "bank blocks it"

Each test: switch relay, ping 1.1.1.1 (latency, jitter, loss), 10 s download from Cloudflare, optional service checks. Rows go into `mvbench.db` immediately, so a stopped run still keeps what it finished. Score = 0.6 × p20 + 0.4 × median Mbps. Failed tests count as 0.

Lockdown mode blocks traffic during a switch rather than leaking it. Expect short drops.

## Scheduled runs (optional)

A run holds the tunnel for about 10 minutes.

The unit expects the clone at `~/Projects/mullvad-speedtest`. Edit the two paths in `systemd/mvbench.service` if you keep it somewhere else.

    cp systemd/mvbench.* ~/.config/systemd/user/
    systemctl --user daemon-reload
    systemctl --user enable --now mvbench.timer
