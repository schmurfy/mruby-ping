class ICMPPinger
  def send_pings(timeout, count)
    ret1 = _send_pings(timeout, count)
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
