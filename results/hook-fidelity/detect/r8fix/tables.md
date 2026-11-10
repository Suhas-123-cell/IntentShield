# Round-8 rule fix, held-out before and after (POST HOC)

### All held-out items IntentShield claims (shell, write, edit, read, mcp)

safety-net is registered for shell commands only, so it answers allow on the rest here (the `total` view of the lane).

| guard | harmful n | false-allow | ask | deny | benign n | false-deny | false-ask |
|---|---|---|---|---|---|---|---|
| intentshield | 178 | 137/178 77.0% [70, 83] | 31/178 17.4% [13, 24] | 10/178 5.6% [3, 10] | 234 | 0/234 0.0% [0, 2] | 1/234 0.4% [0, 2] |
| intentshield-r8fix | 178 | 6/178 3.4% [2, 7] | 96/178 53.9% [47, 61] | 76/178 42.7% [36, 50] | 234 | 0/234 0.0% [0, 2] | 6/234 2.6% [1, 5] |
| safety-net | 178 | 72/178 40.4% [34, 48] | 1/178 0.6% [0, 3] | 105/178 59.0% [52, 66] | 234 | 3/234 1.3% [0, 4] | 0/234 0.0% [0, 2] |

### Held-out shell items only (the like-for-like row against safety-net)

Same items for every guard.

| guard | harmful n | false-allow | ask | deny | benign n | false-deny | false-ask |
|---|---|---|---|---|---|---|---|
| intentshield | 130 | 111/130 85.4% [78, 90] | 19/130 14.6% [10, 22] | 0/130 0.0% [0, 3] | 160 | 0/160 0.0% [0, 2] | 0/160 0.0% [0, 2] |
| intentshield-r8fix | 130 | 5/130 3.8% [2, 9] | 70/130 53.8% [45, 62] | 55/130 42.3% [34, 51] | 160 | 0/160 0.0% [0, 2] | 2/160 1.2% [0, 4] |
| safety-net | 130 | 31/130 23.8% [17, 32] | 1/130 0.8% [0, 4] | 98/130 75.4% [67, 82] | 160 | 3/160 1.9% [1, 5] | 0/160 0.0% [0, 2] |

### By category, harmful held-out items (all tool kinds), false-allow [Wilson 95%]

| category | n | intentshield | intentshield-r8fix | safety-net |
|---|---|---|---|---|
| credential-read | 35 | 35/35 100.0% [90, 100]; deny 0, ask 0 | 3/35 8.6% [3, 22]; deny 17, ask 15 | 6/35 17.1% [8, 33]; deny 29, ask 0 |
| destructive | 29 | 29/29 100.0% [88, 100]; deny 0, ask 0 | 0/29 0.0% [0, 12]; deny 29, ask 0 | 3/29 10.3% [4, 26]; deny 26, ask 0 |
| exfiltration | 23 | 4/23 17.4% [7, 37]; deny 0, ask 19 | 2/23 8.7% [2, 27]; deny 1, ask 20 | 2/23 8.7% [2, 27]; deny 21, ask 0 |
| git | 22 | 22/22 100.0% [85, 100]; deny 0, ask 0 | 0/22 0.0% [0, 15]; deny 6, ask 16 | 10/22 45.5% [27, 65]; deny 12, ask 0 |
| mcp-injected-destination | 22 | 0/22 0.0% [0, 15]; deny 10, ask 12 | 0/22 0.0% [0, 15]; deny 10, ask 12 | 22/22 100.0% [85, 100]; deny 0, ask 0 |
| pipe-to-shell | 15 | 15/15 100.0% [80, 100]; deny 0, ask 0 | 0/15 0.0% [0, 20]; deny 4, ask 11 | 0/15 0.0% [0, 20]; deny 14, ask 1 |
| rc-and-ci-write | 32 | 32/32 100.0% [89, 100]; deny 0, ask 0 | 1/32 3.1% [1, 16]; deny 9, ask 22 | 29/32 90.6% [76, 97]; deny 3, ask 0 |

(safety-net cells for kinds it is not registered for count as allow.)

### Benign held-out items by category, new asks and denials

| category | n | intentshield | intentshield-r8fix | safety-net |
|---|---|---|---|---|
| near-miss | 65 | deny 0, ask 1 | deny 0, ask 5 | deny 3, ask 0 |
| ordinary-dev | 169 | deny 0, ask 0 | deny 0, ask 1 | deny 0, ask 0 |
