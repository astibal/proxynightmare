set pagination off
set confirm off
set $epollout_hits = 0

break epoll::modify if (mask & 4) != 0
commands
    silent
    set $epollout_hits = $epollout_hits + 1
    printf "=== EPOLLOUT re-arm hit %d: socket=%d mask=%d ===\n", $epollout_hits, socket, mask
    thread
    bt 10
    if $epollout_hits >= 3
        detach
        quit
    end
    continue
end

continue
