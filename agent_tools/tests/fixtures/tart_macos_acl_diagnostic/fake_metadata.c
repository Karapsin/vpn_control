/* Controlled ABI endpoint only. No OS metadata or guest access. */
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
static int mode,position,acl_frees,qualifier_frees;
static unsigned char guid[16]={0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x01};
void configure(int value){mode=value;position=-1;acl_frees=qualifier_frees=0;}
int counts(int kind){return kind?qualifier_frees:acl_frees;}
void *acl_get_fd_np(int fd,int type){if(type!=0x100||fd<0){errno=EINVAL;return 0;}if(mode==1){errno=EACCES;return 0;}if(mode==2){errno=ENOENT;return 0;}return(void*)0x1000;}
int acl_valid(void *acl){if(mode==3){errno=EINVAL;return-1;}return acl==(void*)0x1000?0:-1;}
int acl_get_entry(void *acl,int which,void **entry){if(acl!=(void*)0x1000){errno=EINVAL;return-1;}position=which==0?0:position+1;if(mode==4||(!(mode==8)&&position>=2)){errno=EINVAL;return-1;}if(mode==5){errno=EIO;return-1;}*entry=(void*)(uintptr_t)(0x2000+position);return mode==6?1:0;}
int acl_get_tag_type(void *entry,int *tag){*tag=mode==7?99:((uintptr_t)entry%2?2:1);return 0;}
void *acl_get_qualifier(void *entry){return mode==9?0:guid;}
int acl_free(void *value){if(value==(void*)0x1000)acl_frees++;else if(value==guid)qualifier_frees++;else return-1;return mode==10?-1:0;}
int acl_get_permset_mask_np(void *entry,uint64_t *mask){*mask=((uint64_t)1<<60)|((uintptr_t)entry%2?0x1040:0x2022);return mode==11?-1:0;}
int acl_get_flagset_np(void *obj,void **flags){*flags=obj;return mode==12?-1:0;}
int acl_get_flag_np(void *flags,int bit){if(mode==13)return-1;return ((uintptr_t)flags%2&&bit==(1<<4))?1:0;}
struct attrlist{uint16_t bitmapcount,reserved;uint32_t common,vol,dir,file,fork;};
struct reply{uint32_t length,capabilities[4],valid[4];};
int fgetattrlist(int fd,void *request_void,void *output,size_t size,unsigned int options){
 struct attrlist *request=request_void;
 if(fd<0||request->bitmapcount!=5||request->reserved||request->common||request->vol!=0x80020000||request->dir||request->file||request->fork||size!=36||options){errno=EINVAL;return-1;}
 if(mode==14){errno=EPERM;return-1;}struct reply *value=output;memset(output,0,size);value->length=mode==15?40:36;value->capabilities[0]=0x02000000;value->valid[0]=mode==16?0:0x02000000;return 0;
}
int mbr_uid_to_uuid(uint32_t ident,void *output){memcpy(output,guid,16);return mode==17?5:0;}
int mbr_gid_to_uuid(uint32_t ident,void *output){memcpy(output,guid,16);return mode==17?5:0;}

_Static_assert(__builtin_types_compatible_p(__typeof__(&fgetattrlist),int(*)(int,void*,void*,size_t,unsigned int)),"controlled endpoint must match actual LP64 SDK declaration");
