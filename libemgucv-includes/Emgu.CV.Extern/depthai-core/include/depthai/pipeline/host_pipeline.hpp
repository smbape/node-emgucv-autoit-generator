#pragma once


#include <list>
#include <memory>
#include <set>
#include <tuple>
#include <vector>
#include <mutex>

#include <boost/lockfree/spsc_queue.hpp>
#include <boost/lockfree/queue.hpp>

#include "depthai/host_data_packet.hpp"

#include "depthai-shared/stream/stream_info.hpp"
#include "depthai-shared/general/data_observer.hpp"
#include "depthai-shared/stream/stream_data.hpp"

//project
#include "depthai/LockingQueue.hpp"

class HostPipeline
    : public DataObserver<StreamInfo, StreamData>
{
protected:
    const unsigned c_data_queue_size = 30;

    LockingQueue<std::shared_ptr<HostDataPacket>> _data_queue_lf;
    std::list<std::shared_ptr<HostDataPacket>> _consumed_packets; // TODO: temporary solution

    std::set<std::string> _public_stream_names;    // streams that are passed to public methods
    std::set<std::string> _observing_stream_names; // all streams that pipeline is subscribed

public:
    using DataObserver<StreamInfo, StreamData>::observe;


    HostPipeline();
    virtual ~HostPipeline() {}

    std::list<std::shared_ptr<HostDataPacket>> getAvailableDataPackets(bool blocking = false);

    void makeStreamPublic(const std::string& stream_name) { _public_stream_names.insert(stream_name); }

    // TODO: temporary solution
    void consumePackets(bool blocking);
    std::list<std::shared_ptr<HostDataPacket>> getConsumedDataPackets();

private:
    // from DataObserver<StreamInfo, StreamData>
    virtual void onNewData(const StreamInfo& info, const StreamData& data) final;
    // from DataObserver<StreamInfo, StreamData>
    virtual void onNewDataSubject(const StreamInfo &info) final;
};
