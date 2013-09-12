class ICMPPinger
  
  def initialize
    internal_init()
    
    @targets = []
    @init_done = false
  end
  
  def add_target(addr, opts = {})
    @targets << [addr, opts.delete(:routing_table) || 0]
  end
  
  def clear_targets
    @init_done = false
    _clear_targets()
  end
  
  def has_targets?
    @targets.size() > 0
  end
  
  ##
  # @param [Integer] timeout how much time to wait for the replies (in ms)
  # @param [Integer] count how many icmp request to send
  # @param [Integer] delay how much time to wait before each icmp request
  def send_pings(timeout, count = 1, delay = 50, wanted_percentiles = [])
    unless @init_done
      _set_targets(@targets)
      @init_done = true
    end
    
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
      ret2[host] = [sum / latencies.size(), (loss / latencies.size()) * 100, {}]
      unless wanted_percentiles.empty?
        percentiles(latencies, wanted_percentiles).each do |arr|
          p, val = *arr
          ret2[host][-1][p] = val
        end
      end
      
    end
    
    ret2
  end

private
  def percentiles(values, perc)
    values_sorted = values.reject{|v| v == nil }
    values_sorted.sort!
    len = values_sorted.size
    
    if values_sorted.empty?
      {}
    else
      perc.map do |p|
        k = (p*(len-1)+1).floor - 1
        f = (p*(len-1)+1) % 1

        [p, values_sorted[k] + (f * (values_sorted[k+1] - values_sorted[k]))]
      end
    end
  end
    
end
