#!/usr/bin/env python
# coding: utf-8

# # Learning Packet Analysis with Data Science

# In[110]:


from scapy.all import * # Packet manipulation
import pandas as pd # Pandas - Create and Manipulate DataFrames
import numpy as np # Math Stuff (don't worry only used for one line :] )
import binascii # Binary to Ascii 
import seaborn as sns
sns.set(color_codes=True)
get_ipython().run_line_magic('matplotlib', 'inline')


# ### The line below will attempt to sniff 10 packets
# #### You can kill the sniffing operation with the stop button in the notebook

# In[111]:


num_of_packets_to_sniff = 100
pcap = sniff(count=num_of_packets_to_sniff)

# rdpcap returns packet list
## packetlist object can be enumerated 
print(type(pcap))
print(len(pcap))
print(pcap)
pcap[0]


# # Append Krack pcap to current stream

# In[112]:


# rdpcap used to Read Pcap
pcap = pcap +  rdpcap("krack_small.pcap")


# In[113]:


pcap[101]


# # 802.11 FCS/QOS/CCMP Segment
# #### Frames/Packets/Segments each encapsulated layer consists of fields

# # Exploring an item in packet list

# In[167]:


# Radio -> 802.11 -> Layer 2 Segments
# We're only interested in Layers 2 (802.11) 
## When capturing we capture layer 2 frames and beyond

# Retrieving a single item from packet list
radio_frame = pcap[103]
wireless_packet = radio_frame.payload
segment = wireless_packet.payload
dot11_ccmp = segment.payload
data = dot11_ccmp.payload # Retrieve payload that comes after layer 4

# Observe that we just popped off previous layer header
print(radio_frame.summary())
print(wireless_packet.summary())
print(segment.summary())
print(dot11_ccmp.summary())
print(data.summary()) # If blank, empty object

# Complete depiction of paket
## Achieving understanding that these are the fields will enable the ability 
## to ask the data more meaningful questions ie) type of layer 4 segment is defined in layer 3 packet
radio_frame.show()


# ### Understanding object types in scapy and Importing layers

# In[118]:


# Understanding the object types in scapy
print(type(radio_frame))
print(type(wireless_packet))
print(type(segment))
print(type(dot11_ccmp))


# Packets can be filtered on layers ie) radio_frame[scapy.layers.l2.Ether]
radio_type = type(radio_frame)
wireless_type = type(wireless_packet)
qos_type = type(segment)
ccmp_type = type(dot11_ccmp)
print("Radio",pcap[radio_type])
print("802.11", pcap[wireless_type])
print("QoS", pcap[qos_type])
print("CCMP", pcap[ccmp_type])

# Scapy provides this via import statements
from scapy.layers.dot11 import RadioTap
from scapy.layers.dot11 import Dot11FCS
from scapy.layers.dot11 import Dot11QoS
from scapy.layers.dot11 import Dot11CCMP


# # Convert PCAP to DataFrame

# In[134]:


# Collect field names from FCS/QoS/CCMP (These will be columns in DF)
fcs_fields = [field.name for field in Dot11FCS().fields_desc]
qos_fields = [field.name for field in Dot11QoS().fields_desc]
ccmp_fields = [field.name for field in Dot11CCMP().fields_desc]
print(fcs_fields)
dataframe_fields = fcs_fields  + qos_fields + ccmp_fields
print(dataframe_fields)
# Create blank DataFrame
df = pd.DataFrame(columns=dataframe_fields)
for packet in pcap[Dot11FCS]:
    # Field array for each row of DataFrame
    field_values = []
    # Add all IP fields to dataframe
    for field in fcs_fields:
        #print(field)
        try:
            if field == 'cfe' or field == 'addr4':
                # Retrieving number of options defined in IP Header
                #field_values.append(len(packet[Dot11FCS].fields[field]))
                field_values.append(1)
            else:
                field_values.append(packet[Dot11FCS].fields[field])
        except: 
            field_values.append(0)
    #field_values.append(packet.time)
    
    layer_type = type(packet[Dot11FCS].payload)
    #print('--->')
    #print(layer_type)
    for field in qos_fields:
        try:
            field_values.append(packet[layer_type].fields[field])
        except: 
            field_values.append(0)
       
    layer_type1 = type(packet[Dot11FCS].payload.payload)    
    #print(layer_type1)
    #print('--->')
    for field in ccmp_fields:
        try:
            field_values.append(packet[layer_type1].fields[field])
        except:
            field_values.append(None)
    
    # Add row to DF
    df_append = pd.DataFrame([field_values], columns=dataframe_fields)
    df = pd.concat([df, df_append], axis=0)

# Reset Index
df = df.reset_index()
# Drop old index column
df = df.drop(columns="index")


# ### DataFrame Basics

# In[135]:


# Retrieve first row from DataFrame
print(df.iloc[0])

print(df.shape)

# Return first 5 rows
df.head()

# Return last 5 rows
df.tail()

# Return the Source Address for all rows
df['addr1']

# Return Src Address, Dst Address, Src Port, Dst Port
df[['ID','addr1','addr2','fcs','PN0']]


# # Statistics

# In[194]:


# Top Source Adddress
print("# Top Source Address")
print(df['addr3'].describe(),'\n\n')

print("# Top Source Address")
print(df.groupby('addr3').describe(),'\n\n')


# Top Destination Address
print("# Top Destination Address")
print(df['addr1'].describe(),"\n\n")

frequent_address = df['addr3'].describe()['top']

# Who is the top address speaking to
print("# Who is Top Address Speaking to?")
print(df[df['addr3'] == frequent_address]['addr1'].unique(),"\n\n")


print("# Associated id with top source addres")
print(df[df['addr3'] == frequent_address]['SC'].unique(),"\n\n")


print("# associated fcs with top source address")
print(df[df['addr3'] == frequent_address]['fcs'].unique(),"\n\n")


# In[140]:


# Unique Source Addresses
print("Unique Source Addresses")
print(df['addr3'].unique())

print()

# Unique Destination Addresses
print("Unique Destination Addresses")
print(df['addr1'].unique())


# # Graphing

# In[189]:


# Group by Source Address and Payload Sum
source_addresses = (df.groupby("addr3")['SC'].sum()/493*16).head()
print(source_addresses)
source_addresses.plot(kind='barh', title="source Addresses (Bytes Received)",figsize=(8,5))


# In[190]:


# Group by Destination Address and Payload Sum
destination_addresses = (df.groupby("addr1")['SC'].sum()).tail()
print(destination_addresses)
destination_addresses.plot(kind='barh', title="Destination Addresses (Bytes Received)",figsize=(8,5))


# In[188]:


dest_freq=df.groupby('addr3').describe()['SC']['count']
dest_freq.plot(kind='barh', title="Destination Addresses (Bytes Received)",figsize=(8,5))


# In[192]:


dest_freq=df.groupby('addr1').describe()['ID']['count']
dest_freq.plot(kind='barh', title="Destination Addresses (Bytes Received)",figsize=(8,5))


# In[206]:


#groupby("time")['payload'].sum().plot(kind='barh',title="Destination Ports (Bytes Received)",figsize=(8,5))

frequent_address_df = df[df['addr3'] == frequent_address]
x = frequent_address_df['fcs'].tolist()
sns.barplot(x="addr1", y="fcs", data=frequent_address_df[['fcs','addr1']],
            label="Total", color="b").set_title("History of bytes sent by most frequent address")


# # Payload Investigation
