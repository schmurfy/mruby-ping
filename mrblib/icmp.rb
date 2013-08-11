class ICMPPinger
  ##
  # @param [Integer] timeout how much time to wait for the replies (in ms)
  # @param [Integer] count how many icmp request to send
  # @param [Integer] delay how much time to wait before each icmp request
  def send_pings(timeout, count = 1, delay = 50)
    
    # sanity check
    if( delay * count >= timeout )
      raise "delay * count should be higher than timeout !"
    end
    
    ret1 = _send_pings(timeout, count, delay)
    ret2 = {}
    
    # do the maths
    ret1.each do |host, latencies|
      sum = loss = 0
      latencies.each do |n|
        if n
          sum += n
        else
          loss += 1
        end
      end
      
      # [host, sum / latencies.size(), (loss / latencies.size()) * 100]
      ret2[host] = [sum / latencies.size() / 1000, (loss / latencies.size()) * 100]
    end
    
    ret2
  end
end
